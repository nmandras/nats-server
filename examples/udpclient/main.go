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

// Command udpclient is a small test harness that speaks the NATS protocol over
// UDP (optionally DTLS) and exercises basic commands (CONNECT, SUB, PUB).
//
// Usage:
//
//	# Start an embedded server and run the pub/sub demo against it:
//	go run ./examples/udpclient -embed
//
//	# Start an embedded server with DTLS and run the demo over DTLS:
//	go run ./examples/udpclient -embed -dtls
//
//	# Run the demo against an already-running server's UDP port:
//	go run ./examples/udpclient -addr 127.0.0.1:4223
//	go run ./examples/udpclient -addr 127.0.0.1:4223 -dtls -insecure
//
// Note: NATS over UDP is connectionless, so the client must speak first. This
// harness sends CONNECT before expecting the server's INFO.
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/pion/dtls/v3"
)

func main() {
	var (
		addr     = flag.String("addr", "", "UDP host:port of a running server (ignored with -embed)")
		embed    = flag.Bool("embed", false, "start an embedded nats-server with UDP enabled")
		useDTLS  = flag.Bool("dtls", false, "use DTLS instead of plain UDP")
		insecure = flag.Bool("insecure", true, "skip server certificate verification (DTLS)")
		subject  = flag.String("subject", "demo.subject", "subject to subscribe/publish on")
		message  = flag.String("msg", "hello over udp", "message payload to publish")
		count    = flag.Int("count", 3, "number of messages to publish")
	)
	flag.Parse()

	var srv *server.Server
	if *embed {
		var err error
		srv, *addr, err = startEmbeddedServer(*useDTLS)
		if err != nil {
			log.Fatalf("Unable to start embedded server: %v", err)
		}
		defer srv.Shutdown()
		log.Printf("Embedded server UDP listening on %s (dtls=%v)", *addr, *useDTLS)
	}
	if *addr == "" {
		log.Fatal("No server address: pass -addr host:port or use -embed")
	}

	conn, err := dial(*addr, *useDTLS, *insecure)
	if err != nil {
		log.Fatalf("Unable to connect: %v", err)
	}
	defer conn.Close()

	if err := runDemo(conn, *subject, *message, *count); err != nil {
		log.Fatalf("Demo failed: %v", err)
	}
	log.Printf("OK: pub/sub over UDP%s completed successfully", dtlsLabel(*useDTLS))
}

func dtlsLabel(d bool) string {
	if d {
		return "+DTLS"
	}
	return ""
}

// dial returns a net.Conn to the server over plain UDP or DTLS.
func dial(addr string, useDTLS, insecure bool) (net.Conn, error) {
	if !useDTLS {
		return net.Dial("udp", addr)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	raddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	return dtls.Dial("udp", raddr, &dtls.Config{InsecureSkipVerify: insecure})
}

// runDemo performs the CONNECT/SUB/PUB exchange and verifies that the published
// messages are delivered back to our own subscription.
func runDemo(conn net.Conn, subject, message string, count int) error {
	br := bufio.NewReaderSize(conn, 65536)

	// 1) CONNECT first (UDP is connectionless, the client must speak first).
	if err := send(conn, "CONNECT {\"verbose\":false,\"name\":\"udpclient\"}\r\n"); err != nil {
		return err
	}

	// 2) Read the server INFO (sent once it sees our first datagram).
	info, err := readControlLine(br)
	if err != nil {
		return fmt.Errorf("reading INFO: %w", err)
	}
	log.Printf("<- %s", info)
	if !strings.HasPrefix(info, "INFO") {
		return fmt.Errorf("expected INFO, got %q", info)
	}

	// 3) SUB to our subject, then PING to flush and confirm the round trip.
	if err := send(conn, fmt.Sprintf("SUB %s 1\r\nPING\r\n", subject)); err != nil {
		return err
	}
	if err := expectLine(br, "PONG", true); err != nil {
		return err
	}
	log.Printf("Subscribed to %q", subject)

	// 4) PUB a few messages.
	for i := 1; i <= count; i++ {
		payload := fmt.Sprintf("%s #%d", message, i)
		pub := fmt.Sprintf("PUB %s %d\r\n%s\r\n", subject, len(payload), payload)
		if err := send(conn, pub); err != nil {
			return err
		}
		log.Printf("-> PUB %s (%d bytes)", subject, len(payload))
	}

	// 5) Read back the delivered MSGs (and answer any server PING).
	deadline := time.Now().Add(5 * time.Second)
	received := 0
	for received < count {
		conn.SetReadDeadline(deadline)
		line, err := readControlLine(br)
		if err != nil {
			return fmt.Errorf("waiting for MSG (%d/%d received): %w", received, count, err)
		}
		switch {
		case strings.HasPrefix(line, "MSG"):
			payload, err := readMsgPayload(br, line)
			if err != nil {
				return err
			}
			received++
			log.Printf("<- MSG %s: %q", subject, payload)
		case strings.HasPrefix(line, "PING"):
			if err := send(conn, "PONG\r\n"); err != nil {
				return err
			}
		case strings.HasPrefix(line, "-ERR"):
			return fmt.Errorf("server error: %s", line)
		default:
			// INFO updates, +OK, etc. — just log and continue.
			log.Printf("<- %s", line)
		}
	}
	return nil
}

// readControlLine reads a single CRLF-terminated protocol line (without the
// trailing CRLF). bufio transparently reassembles datagrams into a stream.
func readControlLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readMsgPayload reads the payload that follows a "MSG ... <#bytes>" line.
func readMsgPayload(br *bufio.Reader, msgLine string) ([]byte, error) {
	fields := strings.Fields(msgLine)
	if len(fields) < 4 {
		return nil, fmt.Errorf("malformed MSG line: %q", msgLine)
	}
	n, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil {
		return nil, fmt.Errorf("bad MSG size in %q: %w", msgLine, err)
	}
	buf := make([]byte, n+2) // payload + CRLF
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func expectLine(br *bufio.Reader, prefix string, log_ bool) error {
	line, err := readControlLine(br)
	if err != nil {
		return err
	}
	if log_ {
		log.Printf("<- %s", line)
	}
	if !strings.HasPrefix(line, prefix) {
		return fmt.Errorf("expected %q, got %q", prefix, line)
	}
	return nil
}

func send(conn net.Conn, proto string) error {
	_, err := conn.Write([]byte(proto))
	return err
}

// startEmbeddedServer launches an in-process nats-server with the UDP transport
// enabled and returns the server and the UDP host:port to connect to.
func startEmbeddedServer(useDTLS bool) (*server.Server, string, error) {
	const host = "127.0.0.1"
	const udpPort = 4223

	opts := &server.Options{
		Host:   host,
		Port:   4222,
		NoLog:  false,
		NoSigs: true,
		UDP:    server.UDPOpts{Host: host, Port: udpPort, MaxPayload: 1200},
	}

	if useDTLS {
		cert, key, err := locateCerts()
		if err != nil {
			return nil, "", err
		}
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, "", fmt.Errorf("loading certs: %w", err)
		}
		opts.UDP.TLSConfig = &tls.Config{Certificates: []tls.Certificate{pair}}
		opts.UDP.TLSTimeout = 2.0
	}

	srv, err := server.NewServer(opts)
	if err != nil {
		return nil, "", err
	}
	srv.ConfigureLogger()
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		return nil, "", fmt.Errorf("server did not become ready")
	}
	return srv, net.JoinHostPort(host, strconv.Itoa(udpPort)), nil
}

// locateCerts finds the test certificate/key shipped with the repo so the
// embedded DTLS demo works out of the box.
func locateCerts() (cert, key string, err error) {
	candidates := []string{
		"server/configs/certs",
		"../../server/configs/certs",
		filepath.Join(os.Getenv("HOME"), "nats-server", "server", "configs", "certs"),
	}
	for _, dir := range candidates {
		c := filepath.Join(dir, "server.pem")
		k := filepath.Join(dir, "key.pem")
		if fileExists(c) && fileExists(k) {
			return c, k, nil
		}
	}
	return "", "", fmt.Errorf("could not locate test certs (server.pem/key.pem); run from the repo root")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
