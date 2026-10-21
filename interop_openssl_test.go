// Copyright 2026 The go-tls-srp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"bufio"
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestOpenSSLServer runs Client against openssl s_server with a verifier file
// made by openssl srp. It runs only when SRPTLS_TEST_OPENSSL names an OpenSSL
// binary built with SRP. The s_server of OpenSSL 3.0.22, 3.5.9, 3.6.5 and
// 4.0.3 closes the connection during its SRP user lookup, also with its own
// s_client, so the test needs OpenSSL 1.1.1. It passes with 1.1.1w.
func TestOpenSSLServer(t *testing.T) {
	openssl := os.Getenv("SRPTLS_TEST_OPENSSL")
	if openssl == "" {
		t.Skip("set SRPTLS_TEST_OPENSSL to an OpenSSL binary with SRP to run this test")
	}
	version, err := exec.Command(openssl, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("%s version: %v: %s", openssl, err, version)
	}
	t.Logf("peer: %s", bytes.TrimSpace(version))

	dir := t.TempDir()
	vfile := filepath.Join(dir, "srpvfile")
	if err := os.WriteFile(vfile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bits := range []int{1024, 2048, 3072, 4096, 8192} {
		args := []string{"srp", "-srpvfile", vfile, "-add", "-gn", strconv.Itoa(bits), "-passout", "pass:" + testPassword, fmt.Sprintf("device-%d", bits)}
		if out, err := exec.Command(openssl, args...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}

	tests := []struct {
		name     string
		username string
		password string
		minBits  int
		suite    uint16
		// want is the sentinel error the client error must wrap, if the
		// handshake must fail.
		want error
		// refused means the client must refuse the server's group.
		refused bool
	}{
		{name: "2048 AES-256", username: "device-2048", suite: TLS_SRP_SHA_WITH_AES_256_CBC_SHA},
		{name: "3072 AES-128", username: "device-3072", suite: TLS_SRP_SHA_WITH_AES_128_CBC_SHA},
		{name: "4096 AES-256", username: "device-4096", suite: TLS_SRP_SHA_WITH_AES_256_CBC_SHA},
		{name: "8192 AES-256", username: "device-8192", suite: TLS_SRP_SHA_WITH_AES_256_CBC_SHA},
		{name: "1024 with MinGroupBits 1024", username: "device-1024", minBits: 1024, suite: TLS_SRP_SHA_WITH_AES_256_CBC_SHA},
		{name: "1024 refused by default", username: "device-1024", suite: TLS_SRP_SHA_WITH_AES_256_CBC_SHA, refused: true},
		{name: "wrong password", username: "device-2048", password: "wrong", suite: TLS_SRP_SHA_WITH_AES_256_CBC_SHA, want: ErrWrongPassword},
		{name: "unknown user", username: "ghost", suite: TLS_SRP_SHA_WITH_AES_256_CBC_SHA, want: ErrUnknownUsername},
	}
	const exportLabel = "EXPERIMENTAL-srptls"
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverKeyLog := filepath.Join(dir, fmt.Sprintf("keylog-%d", i))
			server := startOpenSSLServer(t, openssl, "-srpvfile", vfile, "-cipher", "SRP",
				"-keymatexport", exportLabel, "-keymatexportlen", "32", "-keylogfile", serverKeyLog)
			conn, err := net.DialTimeout("tcp", server.addr, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(30 * time.Second))

			var keyLog bytes.Buffer
			client := Client(conn, &Config{
				Username:     tt.username,
				Password:     cmp.Or(tt.password, testPassword),
				ServerName:   "localhost",
				MinGroupBits: tt.minBits,
				CipherSuites: []uint16{tt.suite},
				KeyLogWriter: &keyLog,
			})
			err = client.Handshake()
			if tt.want != nil || tt.refused {
				if err == nil {
					t.Fatal("handshake succeeded")
				}
				t.Logf("client error: %v", err)
				if tt.want != nil && !errors.Is(err, tt.want) {
					t.Errorf("client error does not wrap %q", tt.want)
				}
				if tt.refused && !strings.Contains(err.Error(), "below the minimum") {
					t.Errorf("client error does not refuse the group")
				}
				conn.(*net.TCPConn).CloseWrite()
				server.wait(t, "ERROR")
				t.Logf("s_server output:\n%s", server.output())
				return
			}
			if err != nil {
				t.Fatalf("handshake: %v\ns_server output:\n%s", err, server.output())
			}

			state := client.ConnectionState()
			t.Logf("client: version %x, suite %s, EMS %v, tls-unique %X", state.Version, CipherSuiteName(state.CipherSuite), state.ExtendedMasterSecret, state.TLSUnique)
			if state.Version != VersionTLS12 || state.CipherSuite != tt.suite || !state.ExtendedMasterSecret {
				t.Errorf("state = %+v", state)
			}

			// Application data in both directions through s_server's stdin and stdout.
			if _, err := io.WriteString(client, "ping from srptls\n"); err != nil {
				t.Fatal(err)
			}
			server.wait(t, "ping from srptls")
			if _, err := io.WriteString(server.stdin, "pong from openssl\n"); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(client).ReadString('\n')
			if err != nil || line != "pong from openssl\n" {
				t.Fatalf("client read %q, %v", line, err)
			}

			// The same keying material and master secret prove that both ends
			// derived the same premaster secret and transcript.
			ekm, err := state.ExportKeyingMaterial(exportLabel, nil, 32)
			if err != nil {
				t.Fatal(err)
			}
			server.wait(t, fmt.Sprintf("Keying material: %X", ekm))
			server.wait(t, "CIPHER is "+openSSLSuiteName(tt.suite))
			serverLog, err := os.ReadFile(serverKeyLog)
			if err != nil {
				t.Fatal(err)
			}
			// s_server starts its key log file with a comment line.
			if !bytes.Contains(bytes.ToLower(serverLog), bytes.ToLower(keyLog.Bytes())) {
				t.Errorf("key log differs: client %q, s_server %q", keyLog.String(), serverLog)
			}
			t.Logf("s_server output:\n%s", server.output())
		})
	}
}

// openSSLSuiteName returns the OpenSSL name of an SRP cipher suite.
func openSSLSuiteName(id uint16) string {
	switch id {
	case TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
		return "SRP-AES-256-CBC-SHA"
	case TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
		return "SRP-AES-128-CBC-SHA"
	case TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
		return "SRP-3DES-EDE-CBC-SHA"
	}
	return CipherSuiteName(id)
}

// openSSLServer is a running openssl s_server.
type openSSLServer struct {
	addr  string
	stdin io.Writer
	mu    sync.Mutex
	out   bytes.Buffer
}

// output returns what s_server wrote to stdout and stderr so far.
func (s *openSSLServer) output() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.String()
}

// wait waits until the output of s_server contains text.
func (s *openSSLServer) wait(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(s.output(), text) {
		if time.Now().After(deadline) {
			t.Fatalf("s_server output lacks %q:\n%s", text, s.output())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Write appends s_server output under the lock.
func (s *openSSLServer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.Write(p)
}

// startOpenSSLServer starts openssl s_server for one connection on a free
// loopback port and waits until it accepts connections.
func startOpenSSLServer(t *testing.T, openssl string, args ...string) *openSSLServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &openSSLServer{addr: l.Addr().String()}
	l.Close()

	args = append([]string{"s_server", "-accept", s.addr, "-naccept", "1", "-nocert"}, args...)
	cmd := exec.Command(openssl, args...)
	cmd.Stdout = s
	cmd.Stderr = s
	// s_server ends the connection when its stdin is closed, so the pipe
	// stays open until the test ends.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	s.stdin = stdin
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	t.Logf("openssl %s", strings.Join(args, " "))
	s.wait(t, "ACCEPT")
	return s
}
