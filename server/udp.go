// Copyright 2024 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/transport/v3/udp"
)

var (
	errUDPUserMixWithUsersNKeys      = errors.New("udp authentication username not compatible with presence of users/nkeys")
	errUDPTokenMixWithUsersNKeys     = errors.New("udp authentication token not compatible with presence of users/nkeys")
	errUDPTLSMapNotSupported         = errors.New("udp: tls verify_and_map is not supported (DTLS is terminated at the listener)")
	errUDPTLSPinnedCertsNotSupported = errors.New("udp: tls pinned_certs is not supported (DTLS is terminated at the listener)")
)

const (
	// Default maximum payload accepted/emitted on a UDP client connection.
	// Kept conservatively under a common path MTU (minus IP/UDP and, when
	// DTLS is used, record overhead) to avoid fragile IP fragmentation.
	defaultUDPMaxPayload = int32(1200)

	// Upper bound for a single UDP datagram we will read into. This is the
	// maximum theoretical UDP payload size and is only used to size the
	// read scratch buffer so that a datagram is never silently truncated.
	udpMaxDatagramSize = 65535
)

// srvUDP holds the state for the UDP (and optional DTLS) transport. It mirrors
// the pattern used by srvMQTT/srvWebsocket.
type srvUDP struct {
	listener     net.Listener
	listenerErr  error
	authOverride bool

	// connectURLs are the UDP endpoints advertised to clients (and routes).
	connectURLs []string

	// Immutable fields, set once in startUDP and read without lock when
	// generating the client INFO protocol.
	tls  bool
	host string
	port int
}

// udpConn adapts a datagram-oriented net.Conn (as returned by the pion UDP or
// DTLS listener) so that the rest of the server can treat it like an ordered
// byte stream. This is required because:
//
//   - The NATS parser (readLoop) is stateful across reads and the pion read
//     buffer discards any datagram bytes that do not fit in the buffer passed
//     to Read(). We therefore read whole datagrams into a max-sized scratch and
//     hand them out in stream-sized chunks.
//   - flushOutbound writes via net.Buffers, whose individual buffers can be far
//     larger than a datagram. We split each Write into at most wmax bytes so we
//     never attempt to send an over-sized datagram.
//
// Note: this provides a stream *presentation* only. UDP does not retransmit or
// reorder, so a lost or reordered datagram will corrupt the per-peer stream.
// Plain UDP is therefore only safe on lossless/controlled links; DTLS adds
// integrity but not reliability.
type udpConn struct {
	net.Conn
	rbuf    []byte // unread remainder of the last datagram
	scratch []byte // reusable datagram read buffer
	wmax    int    // maximum bytes per Write datagram
}

// isUDPTransport returns true if this client connection uses the UDP/DTLS
// transport.
func (c *client) isUDPTransport() bool {
	return c.flags.isSet(isUDP)
}

func newUDPConn(c net.Conn, wmax int) *udpConn {
	if wmax <= 0 {
		wmax = int(defaultUDPMaxPayload)
	}
	return &udpConn{
		Conn:    c,
		scratch: make([]byte, udpMaxDatagramSize),
		wmax:    wmax,
	}
}

func (c *udpConn) Read(p []byte) (int, error) {
	if len(c.rbuf) == 0 {
		n, err := c.Conn.Read(c.scratch)
		if n > 0 {
			c.rbuf = c.scratch[:n]
		} else {
			return 0, err
		}
		// Any io.ErrShortBuffer is impossible here since scratch is sized to
		// the maximum datagram, so we intentionally ignore err when n > 0.
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *udpConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > c.wmax {
			chunk = p[:c.wmax]
		}
		n, err := c.Conn.Write(chunk)
		total += n
		if err != nil {
			return total, err
		}
		p = p[len(chunk):]
	}
	return total, nil
}

// startUDP starts the UDP listener (optionally wrapped with DTLS) and the
// accept loop that turns each UDP peer into a regular NATS client.
func (s *Server) startUDP() {
	if s.isShuttingDown() {
		return
	}

	sopts := s.getOpts()
	o := &sopts.UDP

	port := o.Port
	if port == -1 {
		port = 0
	}
	hp := net.JoinHostPort(o.Host, strconv.Itoa(port))
	laddr, err := net.ResolveUDPAddr("udp", hp)
	if err != nil {
		s.Fatalf("Unable to resolve UDP address %q: %v", hp, err)
		return
	}

	dtlsEnabled := o.TLSConfig != nil && !o.NoDTLS

	s.mu.Lock()

	var hl net.Listener
	scheme := "udp"
	if dtlsEnabled {
		dcfg, derr := udpDTLSConfigFromTLS(o.TLSConfig, o)
		if derr != nil {
			s.udp.listenerErr = derr
			s.mu.Unlock()
			s.Fatalf("Unable to build DTLS config: %v", derr)
			return
		}
		// dtls.Listen builds its own per-peer datagram demux internally and
		// performs the DTLS handshake during Accept(). The accepted conn is a
		// *dtls.Conn (a net.Conn) exposing plaintext application data, so the
		// standard client path never needs to do a TLS handshake on it.
		hl, err = dtls.Listen("udp", laddr, dcfg)
		scheme = "dtls"
	} else {
		// pion's UDP listener demuxes incoming datagrams per remote address
		// into individual stream-like net.Conns.
		hl, err = udp.Listen("udp", laddr)
	}
	s.udp.listenerErr = err
	if err != nil {
		s.mu.Unlock()
		s.Fatalf("Unable to listen for UDP connections: %v", err)
		return
	}

	// Security note: plain UDP source addresses are not validated, so the
	// listener can be used as a reflection/amplification vector (a small
	// spoofed datagram elicits the larger INFO protocol) and is trivially
	// flooded with spoofed sources. DTLS mitigates this via its
	// HelloVerifyRequest cookie exchange. Plain UDP should therefore only be
	// exposed on trusted/controlled networks.
	if !dtlsEnabled {
		s.Warnf("UDP transport without DTLS does not validate source addresses; " +
			"only expose it on trusted networks (use DTLS otherwise)")
	}

	if port == 0 {
		o.Port = hl.Addr().(*net.UDPAddr).Port
	}
	s.udp.listener = hl
	s.udp.tls = dtlsEnabled
	s.udp.host = o.Host
	s.udp.port = o.Port

	// Build the advertised connect URLs and update the server INFO so clients
	// (and routes) learn about the UDP endpoint(s).
	if curls, cerr := s.getConnectURLs(o.Advertise, o.Host, o.Port); cerr != nil {
		s.Errorf("Unable to get UDP connect URLs: %v", cerr)
	} else {
		s.udp.connectURLs = curls
		s.info.UDPConnectURLs = curls
	}
	s.info.DTLSAvailable = dtlsEnabled
	s.info.DTLSRequired = dtlsEnabled

	s.Noticef("Listening for UDP client connections on %s://%s:%d", scheme, o.Host, o.Port)

	go s.acceptConnections(hl, "UDP", func(conn net.Conn) { s.createUDPClient(conn) }, nil)

	s.mu.Unlock()
}

// createUDPClient turns an accepted UDP/DTLS connection into a regular NATS
// client. UDP clients speak the standard NATS protocol, so this mirrors
// createClientEx, minus the TLS handshake handling (DTLS, when enabled, is
// already terminated by the listener) and TCP-only features (TLSHandshakeFirst,
// AllowNonTLS, proxy protocol).
//
// Note: because UDP is connectionless, the pion listener only surfaces a peer
// (and we only get here) once the client has sent its first datagram. Unlike
// TCP, the server therefore cannot send the initial INFO before the client
// speaks. UDP clients must initiate by sending CONNECT (optionally preceded by
// PING); the server then replies with INFO and the standard exchange proceeds.
func (s *Server) createUDPClient(conn net.Conn) *client {
	opts := s.getOpts()

	maxPay := opts.UDP.MaxPayload
	if maxPay <= 0 {
		maxPay = defaultUDPMaxPayload
	}
	// Never exceed the server-wide max payload.
	if smp := int32(opts.MaxPayload); smp > 0 && smp < maxPay {
		maxPay = smp
	}
	maxSubs := int32(opts.MaxSubs)
	if maxSubs == 0 {
		maxSubs = -1
	}
	now := time.Now()

	// Wrap the datagram conn so the read/write loops see an ordered stream and
	// never over/under-size a datagram.
	nc := newUDPConn(conn, int(maxPay))

	c := &client{
		srv:   s,
		nc:    nc,
		opts:  defaultOpts,
		mpay:  maxPay,
		msubs: maxSubs,
		start: now,
		last:  now,
	}
	c.flags.set(isUDP)

	c.registerWithAccount(s.globalAccount())

	var info Info
	var authRequired bool

	s.mu.Lock()
	info = s.copyInfo()
	if s.nonceRequired() {
		var raw [nonceLen]byte
		nonce := raw[:]
		s.generateNonce(nonce)
		info.Nonce = string(nonce)
	}
	c.nonce = []byte(info.Nonce)
	authRequired = info.AuthRequired || s.udp.authOverride
	info.AuthRequired = authRequired

	if authRequired && opts.UDP.NoAuthUser != _EMPTY_ {
		info.AuthRequired = false
	}
	s.totalClients++
	s.mu.Unlock()

	c.mu.Lock()
	if authRequired {
		c.flags.set(expectConnect)
	}
	c.initClient()
	c.Debugf("UDP client connection created")

	// Clamp the max payload to the UDP datagram budget. This is done after
	// initClient/registerWithAccount, which set c.mpay from the account/server
	// limits, so that the UDP cap can only lower (never raise) the limit.
	if maxPay > 0 && (c.mpay <= 0 || maxPay < c.mpay) {
		c.mpay = maxPay
	}

	// DTLS is already done at the listener, so TLS is never required here.
	info.TLSRequired, info.TLSAvailable = false, false
	infoBytes := c.generateClientInfoJSON(info, true)
	c.sendProtoNow(infoBytes)
	c.mu.Unlock()

	s.mu.Lock()
	if !s.isRunning() || s.ldm {
		if s.isShuttingDown() {
			conn.Close()
		}
		s.mu.Unlock()
		return c
	}
	if opts.MaxConn < 0 || (opts.MaxConn > 0 && len(s.clients) >= opts.MaxConn) {
		s.mu.Unlock()
		c.maxConnExceeded()
		return nil
	}
	s.clients[c.cid] = c
	s.mu.Unlock()

	c.mu.Lock()
	if c.isClosed() {
		c.mu.Unlock()
		c.closeConnection(WriteError)
		return nil
	}

	if authRequired {
		timeout := opts.AuthTimeout
		if opts.UDP.AuthTimeout != 0 {
			timeout = opts.UDP.AuthTimeout
		}
		c.setAuthTimer(secondsToDuration(timeout))
	}

	// Set the Ping timer. Will be reset once connect was received. This is how
	// we detect a UDP peer that has silently gone away (no FIN over UDP).
	c.setPingTimer()

	s.startGoRoutine(func() { c.readLoop(nil) })
	s.startGoRoutine(func() { c.writeLoop() })

	c.mu.Unlock()

	return c
}

// udpDTLSConfigFromTLS translates the standard *tls.Config produced by
// GenTLSConfig into a pion *dtls.Config. DTLS does not accept a *tls.Config
// directly and uses its own cipher-suite identifiers.
func udpDTLSConfigFromTLS(tc *tls.Config, o *UDPOpts) (*dtls.Config, error) {
	cfg := &dtls.Config{
		Certificates:       tc.Certificates,
		ClientCAs:          tc.ClientCAs,
		RootCAs:            tc.RootCAs,
		ClientAuth:         dtls.ClientAuthType(tc.ClientAuth),
		InsecureSkipVerify: tc.InsecureSkipVerify,
	}
	if cs := mapDTLSCipherSuites(tc.CipherSuites); len(cs) > 0 {
		cfg.CipherSuites = cs
	}
	return cfg, nil
}

// mapDTLSCipherSuites translates the subset of stdlib TLS cipher suites that
// have a DTLS-supported equivalent in pion. Unsupported suites are dropped. A
// nil/empty result tells pion to use its secure defaults.
func mapDTLSCipherSuites(suites []uint16) []dtls.CipherSuiteID {
	if len(suites) == 0 {
		return nil
	}
	out := make([]dtls.CipherSuiteID, 0, len(suites))
	for _, s := range suites {
		switch s {
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			out = append(out, dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
		case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			out = append(out, dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
			out = append(out, dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
		case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			out = append(out, dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
		case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			out = append(out, dtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
		case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			out = append(out, dtls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
			// Suites without a DTLS-supported equivalent (e.g. AES-128-CBC) are
			// intentionally dropped rather than substituted with a different
			// suite, so we never silently change the configured security level.
		}
	}
	return out
}

// validateUDPOptions validates the UDP transport related options.
func validateUDPOptions(o *Options) error {
	uo := &o.UDP
	// If no port is defined, we don't care about other options.
	if uo.Port == 0 {
		return nil
	}
	// Certificate-based controls cannot be honored because DTLS is terminated
	// at the listener and never flows through the standard TLS handshake path
	// (which is what enforces cert->user mapping and pinned certs). Fail closed
	// rather than silently ignore these security controls.
	if uo.TLSMap {
		return errUDPTLSMapNotSupported
	}
	if len(uo.TLSPinnedCerts) > 0 {
		return errUDPTLSPinnedCertsNotSupported
	}
	// If there is a NoAuthUser, we need to have Users defined and the user to
	// be present.
	if uo.NoAuthUser != _EMPTY_ {
		if err := validateNoAuthUser(o, uo.NoAuthUser); err != nil {
			return err
		}
	}
	// Token/Username not possible if there are users/nkeys.
	if len(o.Users) > 0 || len(o.Nkeys) > 0 {
		if uo.Username != _EMPTY_ {
			return errUDPUserMixWithUsersNKeys
		}
		if uo.Token != _EMPTY_ {
			return errUDPTokenMixWithUsersNKeys
		}
	}
	return nil
}

// udpConfigAuth checks if any auth configuration has been provided for UDP
// clients and updates a boolean indicating an override.
// Server lock is held on entry.
func (s *Server) udpConfigAuth(opts *UDPOpts) {
	s.udp.authOverride = opts.Username != _EMPTY_ || opts.Token != _EMPTY_ || opts.NoAuthUser != _EMPTY_
}
