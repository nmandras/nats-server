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
	"bufio"
	"crypto/tls"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
)

var (
	udpInfoRe = regexp.MustCompile(`INFO\s+([^\r\n]+)\r\n`)
	udpPongRe = regexp.MustCompile(`PONG\r\n`)
	udpMsgRe  = regexp.MustCompile(`MSG\s+([^\r\n]+)\r\n`)
	udpErrRe  = regexp.MustCompile(`-ERR\s+'([^']+)'\r\n`)
)

// udpExpect reads datagrams from c, accumulating until re matches, and returns
// the full buffer read so far.
func udpExpect(t testing.TB, c net.Conn, re *regexp.Regexp) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	var buf []byte
	tmp := make([]byte, 4096)
	for i := 0; i < 50; i++ {
		n, err := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if re.Match(buf) {
				return buf
			}
		}
		if err != nil {
			break
		}
	}
	t.Fatalf("Expected to match %q, got %q", re, buf)
	return nil
}

// dialUDP returns a plain UDP net.Conn to the server's UDP port.
func dialUDP(t testing.TB, s *Server) net.Conn {
	t.Helper()
	o := s.getOpts()
	addr := net.JoinHostPort(o.UDP.Host, strconv.Itoa(o.UDP.Port))
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Error dialing UDP: %v", err)
	}
	return c
}

// dialDTLS returns a DTLS net.Conn to the server's UDP port.
func dialDTLS(t testing.TB, s *Server, cfg *dtls.Config) net.Conn {
	t.Helper()
	o := s.getOpts()
	raddr := &net.UDPAddr{IP: net.ParseIP(o.UDP.Host), Port: o.UDP.Port}
	c, err := dtls.Dial("udp", raddr, cfg)
	if err != nil {
		t.Fatalf("Error dialing DTLS: %v", err)
	}
	return c
}

func runUDPServer(t testing.TB, configure func(*Options)) *Server {
	t.Helper()
	o := DefaultOptions()
	o.UDP = UDPOpts{Host: "127.0.0.1", Port: -1}
	if configure != nil {
		configure(o)
	}
	return RunServer(o)
}

func TestParseUDP(t *testing.T) {
	conf := createConfFile(t, []byte(`
		udp {
			listen: "127.0.0.1:4223"
			advertise: "udp.example.com:4223"
			no_advertise: true
			max_payload: 1200
			authorization {
				token: "s3cr3t"
				timeout: 2.0
			}
		}
	`))
	o, err := ProcessConfigFile(conf)
	if err != nil {
		t.Fatalf("Error processing config: %v", err)
	}
	if o.UDP.Host != "127.0.0.1" || o.UDP.Port != 4223 {
		t.Fatalf("Unexpected host/port: %s:%d", o.UDP.Host, o.UDP.Port)
	}
	if o.UDP.Advertise != "udp.example.com:4223" {
		t.Fatalf("Unexpected advertise: %q", o.UDP.Advertise)
	}
	if !o.UDP.NoAdvertise {
		t.Fatalf("Expected no_advertise to be true")
	}
	if o.UDP.MaxPayload != 1200 {
		t.Fatalf("Unexpected max_payload: %d", o.UDP.MaxPayload)
	}
	if o.UDP.Token != "s3cr3t" || o.UDP.AuthTimeout != 2.0 {
		t.Fatalf("Unexpected auth: token=%q timeout=%v", o.UDP.Token, o.UDP.AuthTimeout)
	}
}

func TestParseUDPWithDTLS(t *testing.T) {
	conf := createConfFile(t, []byte(`
		udp {
			port: 4223
			tls {
				cert_file: "./configs/certs/server.pem"
				key_file: "./configs/certs/key.pem"
				timeout: 3.0
			}
		}
	`))
	o, err := ProcessConfigFile(conf)
	if err != nil {
		t.Fatalf("Error processing config: %v", err)
	}
	if o.UDP.TLSConfig == nil {
		t.Fatalf("Expected TLSConfig to be set for DTLS")
	}
	if o.UDP.TLSTimeout != 3.0 {
		t.Fatalf("Unexpected TLS timeout: %v", o.UDP.TLSTimeout)
	}
}

func TestValidateUDPOptions(t *testing.T) {
	// No port => no validation.
	o := &Options{}
	if err := validateUDPOptions(o); err != nil {
		t.Fatalf("Expected no error with no UDP port, got %v", err)
	}
	// Token mixed with users should fail.
	o = &Options{
		UDP:   UDPOpts{Port: 4223, Token: "abc"},
		Users: []*User{{Username: "a", Password: "b"}},
	}
	if err := validateUDPOptions(o); err != errUDPTokenMixWithUsersNKeys {
		t.Fatalf("Expected token/users error, got %v", err)
	}
	// NoAuthUser that does not exist should fail.
	o = &Options{UDP: UDPOpts{Port: 4223, NoAuthUser: "ghost"}}
	if err := validateUDPOptions(o); err == nil {
		t.Fatalf("Expected error for unknown no_auth_user")
	}
	// TLSMap is not supported (DTLS terminated at listener) => fail closed.
	o = &Options{UDP: UDPOpts{Port: 4223, TLSMap: true}}
	if err := validateUDPOptions(o); err != errUDPTLSMapNotSupported {
		t.Fatalf("Expected TLSMap-not-supported error, got %v", err)
	}
	// Pinned certs are not supported => fail closed.
	o = &Options{UDP: UDPOpts{Port: 4223, TLSPinnedCerts: PinnedCertSet{"abc": struct{}{}}}}
	if err := validateUDPOptions(o); err != errUDPTLSPinnedCertsNotSupported {
		t.Fatalf("Expected pinned-certs-not-supported error, got %v", err)
	}
}

// TestUDPAuthTokenEnforced is a security regression test: a UDP-specific auth
// override (here a token) must actually be enforced, even when no global client
// auth is configured. A missing or wrong token must be rejected; the correct
// token must be accepted.
func TestUDPAuthTokenEnforced(t *testing.T) {
	s := runUDPServer(t, func(o *Options) {
		o.UDP.Token = "s3cr3t"
	})
	defer s.Shutdown()

	try := func(connect string) (pong, errd bool) {
		c := dialUDP(t, s)
		defer c.Close()
		if _, err := c.Write([]byte(connect)); err != nil {
			t.Fatalf("write: %v", err)
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		br := bufio.NewReaderSize(c, 8192)
		for i := 0; i < 10; i++ {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			switch {
			case strings.HasPrefix(line, "PONG"):
				return true, false
			case strings.HasPrefix(line, "-ERR"):
				return false, true
			}
		}
		return false, false
	}

	if pong, _ := try("CONNECT {}\r\nPING\r\n"); pong {
		t.Fatal("auth bypass: connection without token was authorized")
	}
	if pong, _ := try("CONNECT {\"auth_token\":\"wrong\"}\r\nPING\r\n"); pong {
		t.Fatal("auth bypass: connection with wrong token was authorized")
	}
	if pong, _ := try("CONNECT {\"auth_token\":\"s3cr3t\"}\r\nPING\r\n"); !pong {
		t.Fatal("valid token was not authorized")
	}
}

func TestUDPClientConnect(t *testing.T) {
	s := runUDPServer(t, nil)
	defer s.Shutdown()

	c := dialUDP(t, s)
	defer c.Close()

	// UDP is connectionless: the server cannot send INFO until the client
	// speaks first, so the client initiates with CONNECT+PING.
	if _, err := c.Write([]byte("CONNECT {\"verbose\":false}\r\nPING\r\n")); err != nil {
		t.Fatalf("Error writing: %v", err)
	}
	udpExpect(t, c, udpInfoRe)
	udpExpect(t, c, udpPongRe)
}

func TestUDPPubSub(t *testing.T) {
	s := runUDPServer(t, nil)
	defer s.Shutdown()

	sub := dialUDP(t, s)
	defer sub.Close()
	if _, err := sub.Write([]byte("CONNECT {\"verbose\":false}\r\nSUB foo 1\r\nPING\r\n")); err != nil {
		t.Fatalf("Error writing: %v", err)
	}
	udpExpect(t, sub, udpInfoRe)
	udpExpect(t, sub, udpPongRe)

	pub := dialUDP(t, s)
	defer pub.Close()
	if _, err := pub.Write([]byte("CONNECT {\"verbose\":false}\r\nPUB foo 5\r\nhello\r\nPING\r\n")); err != nil {
		t.Fatalf("Error writing: %v", err)
	}
	udpExpect(t, pub, udpInfoRe)
	udpExpect(t, pub, udpPongRe)

	buf := udpExpect(t, sub, udpMsgRe)
	if m := udpMsgRe.FindSubmatch(buf); m == nil {
		t.Fatalf("Did not receive MSG, got %q", buf)
	}
}

func TestUDPInfoAdvertise(t *testing.T) {
	s := runUDPServer(t, nil)
	defer s.Shutdown()

	c := dialUDP(t, s)
	defer c.Close()
	if _, err := c.Write([]byte("PING\r\n")); err != nil {
		t.Fatalf("Error writing: %v", err)
	}
	buf := udpExpect(t, c, udpInfoRe)
	js := udpInfoRe.FindSubmatch(buf)[1]
	var info Info
	if err := json.Unmarshal(js, &info); err != nil {
		t.Fatalf("Error unmarshalling INFO: %v", err)
	}
	// Like websocket, a UDP client gets the UDP endpoints folded into
	// connect_urls (and its host/port set to the UDP listener), while the
	// udp_connect_urls field itself is cleared in the client-facing INFO.
	udpPort := s.getOpts().UDP.Port
	if info.Port != udpPort {
		t.Fatalf("Expected INFO port to be the UDP port %d, got %d", udpPort, info.Port)
	}
	if len(info.ClientConnectURLs) == 0 {
		t.Fatalf("Expected connect_urls to advertise the UDP endpoint, got: %s", js)
	}
	if info.DTLSAvailable || info.DTLSRequired {
		t.Fatalf("Did not expect DTLS flags for plain UDP, got: %s", js)
	}
}

func TestUDPMaxPayloadClamp(t *testing.T) {
	s := runUDPServer(t, func(o *Options) {
		o.UDP.MaxPayload = 16
	})
	defer s.Shutdown()

	c := dialUDP(t, s)
	defer c.Close()
	if _, err := c.Write([]byte("CONNECT {\"verbose\":false}\r\nPING\r\n")); err != nil {
		t.Fatalf("Error writing: %v", err)
	}
	buf := udpExpect(t, c, udpInfoRe)
	var info Info
	json.Unmarshal(udpInfoRe.FindSubmatch(buf)[1], &info)
	if info.MaxPayload != 16 {
		t.Fatalf("Expected max_payload 16, got %d", info.MaxPayload)
	}
	udpExpect(t, c, udpPongRe)

	// Publishing more than max_payload bytes must be rejected.
	if _, err := c.Write([]byte("PUB foo 20\r\n12345678901234567890\r\n")); err != nil {
		t.Fatalf("Error writing: %v", err)
	}
	udpExpect(t, c, udpErrRe)
}

func TestUDPDTLS(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("./configs/certs/server.pem", "./configs/certs/key.pem")
	if err != nil {
		t.Fatalf("Error loading server cert: %v", err)
	}
	s := runUDPServer(t, func(o *Options) {
		o.UDP.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		o.UDP.TLSTimeout = 2.0
	})
	defer s.Shutdown()

	// INFO should advertise DTLS now.
	c := dialDTLS(t, s, &dtls.Config{InsecureSkipVerify: true})
	defer c.Close()
	if _, err := c.Write([]byte("CONNECT {\"verbose\":false}\r\nPING\r\n")); err != nil {
		t.Fatalf("Error writing over DTLS: %v", err)
	}
	buf := udpExpect(t, c, udpInfoRe)
	var info Info
	json.Unmarshal(udpInfoRe.FindSubmatch(buf)[1], &info)
	if !info.DTLSAvailable || !info.DTLSRequired {
		t.Fatalf("Expected DTLS flags to be set, got: %s", buf)
	}
	udpExpect(t, c, udpPongRe)
}

func TestUDPReadyForConnections(t *testing.T) {
	s := runUDPServer(t, nil)
	defer s.Shutdown()
	if !s.ReadyForConnections(2 * time.Second) {
		t.Fatal("Server not ready, UDP listener likely failed")
	}
	s.mu.RLock()
	l := s.udp.listener
	s.mu.RUnlock()
	if l == nil {
		t.Fatal("Expected UDP listener to be set")
	}
}

func TestUDPShutdown(t *testing.T) {
	s := runUDPServer(t, nil)
	c := dialUDP(t, s)
	defer c.Close()
	c.Write([]byte("PING\r\n"))
	udpExpect(t, c, udpInfoRe)

	s.Shutdown()

	s.mu.RLock()
	l := s.udp.listener
	s.mu.RUnlock()
	if l != nil {
		t.Fatal("Expected UDP listener to be nil after shutdown")
	}
}
