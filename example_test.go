// Copyright 2026 The go-tls-srp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The documentation site includes the code between the "--8<--" markers, so the code it shows is
// compiled and, for examples with an Output comment, run by go test.

package srptls_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	srptls "github.com/misiektoja/go-tls-srp"
)

// Example runs a TLS-SRP server and a client in one process. The server
// stores only the verifier of device-1 and the client signs in with the
// password the verifier was made from.
func Example() {
	// --8<-- [start:verifier]
	group, err := srptls.GroupByBits(3072)
	if err != nil {
		log.Fatal(err)
	}
	salt, err := srptls.NewSalt(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	stored, err := srptls.NewVerifier(group, []byte("device-1"), []byte("secret"), salt)
	if err != nil {
		log.Fatal(err)
	}
	// --8<-- [end:verifier]

	// --8<-- [start:server]
	l, err := srptls.Listen("tcp", "127.0.0.1:0", &srptls.Config{
		GetVerifier: func(info *srptls.ClientHelloInfo) (*srptls.Verifier, error) {
			if info.Username == "device-1" {
				return stored, nil
			}
			return nil, srptls.ErrUnknownUsername
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// The library sets no handshake deadline.
		c.SetDeadline(time.Now().Add(10 * time.Second))
		conn := c.(*srptls.Conn)
		if err := conn.Handshake(); err != nil {
			log.Print(err)
			return
		}
		fmt.Fprintf(conn, "hello %s\n", conn.ConnectionState().SRPUsername)
	}()
	// --8<-- [end:server]

	// --8<-- [start:client]
	raw, err := net.DialTimeout("tcp", l.Addr().String(), 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	conn := srptls.Client(raw, &srptls.Config{
		Username:   "device-1",
		Password:   "secret",
		ServerName: "localhost",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = conn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		log.Fatal(err)
	}

	greeting, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	state := conn.ConnectionState()
	fmt.Print(greeting)
	fmt.Println(srptls.CipherSuiteName(state.CipherSuite))
	fmt.Println("extended master secret:", state.ExtendedMasterSecret)
	fmt.Println("tls-unique bytes:", len(state.TLSUnique))
	conn.Close()
	// --8<-- [end:client]
	l.Close()

	// Output:
	// hello device-1
	// TLS_SRP_SHA_WITH_AES_256_CBC_SHA
	// extended master secret: true
	// tls-unique bytes: 12
}

// Example_openSSLVerifierFile imports a user from an srpvfile written by
// openssl srp and signs in with the password the verifier was made from.
func Example_openSSLVerifierFile() {
	// --8<-- [start:srpvfile]
	// openssl srp -srpvfile srpvfile -add -gn 2048 -passout pass:secret device-1
	// wrote this line. Its fields are separated by tabs: the entry type, the
	// verifier, the salt, the username, the group and an info field.
	line := "" +
		"V\t" +
		"09XhP7Rygmz11SS0DG4K5xiZG1ZQd9EWGKrcj8hrTflO.jHVanjs8pty5i75DwZL" +
		"0S4WoSFE/MHquQvcDR3k6mdrPw4ICmL.7BAwSY2IZNbnq6DwO0Z0iKDNjtJVX00K" +
		"GXD/i/CbNXN/DLRdGksYUPp8y3B4XWmxGYls38r1bkXMcX0kKeVO8hJGV/lO0vvc" +
		"p2Fw8iap2MtiDX0vFRUE7WX2MtU9TyHM.z1Pc8Z894v9H2l1oKw5YcbXAce2OsCJ" +
		"T5YmQU3FQo5KJeYuvOfmZAer0Ur24rHfUzC9Fie3tJQ1STQ84j2J1CMvbfO5biZf" +
		"rPy6azssYuu6VtcIfoZ1Ae\t" +
		"8RgioHW1582bhjJhyBvFIRK4Up7\tdevice-1\t2048\t"

	// OpenSSL writes the verifier and the salt as numbers in its own base 64
	// alphabet, without padding and without leading zero digits.
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./"
	decode := func(s string) ([]byte, error) {
		n := new(big.Int)
		for i := 0; i < len(s); i++ {
			digit := strings.IndexByte(alphabet, s[i])
			if digit < 0 {
				return nil, fmt.Errorf("invalid character %q", s[i])
			}
			n.Lsh(n, 6).Or(n, big.NewInt(int64(digit)))
		}
		// Bytes drops leading zero bytes, as OpenSSL does with the salt.
		return n.Bytes(), nil
	}

	fields := strings.Split(line, "\t")
	if len(fields) != 6 || fields[0] != "V" {
		log.Fatal("not the entry of a valid user")
	}
	value, err := decode(fields[1])
	if err != nil {
		log.Fatal(err)
	}
	salt, err := decode(fields[2])
	if err != nil {
		log.Fatal(err)
	}
	// For the groups OpenSSL ships, the group field is the prime size in bits.
	bits, err := strconv.Atoi(fields[4])
	if err != nil {
		log.Fatal(err)
	}
	group, err := srptls.GroupByBits(bits)
	if err != nil {
		log.Fatal(err)
	}
	username := fields[3]
	stored := &srptls.Verifier{Group: group, Salt: salt, Value: value}
	if err := stored.Validate(); err != nil {
		log.Fatal(err)
	}
	// --8<-- [end:srpvfile]

	clientConn, serverConn := net.Pipe()
	server := srptls.Server(serverConn, &srptls.Config{
		GetVerifier: func(info *srptls.ClientHelloInfo) (*srptls.Verifier, error) {
			if info.Username == username {
				return stored, nil
			}
			return nil, srptls.ErrUnknownUsername
		},
	})
	errc := make(chan error, 1)
	go func() { errc <- server.Handshake() }()
	client := srptls.Client(clientConn, &srptls.Config{Username: "device-1", Password: "secret"})
	if err := client.Handshake(); err != nil {
		log.Fatal(err)
	}
	if err := <-errc; err != nil {
		log.Fatal(err)
	}
	fmt.Println(server.ConnectionState().SRPUsername, group.Bits())
	clientConn.Close()
	serverConn.Close()
	// Output: device-1 2048
}

type connKey struct{}

// Example_httpServer serves HTTPS over TLS-SRP. net/http leaves Request.TLS
// nil for connections that are not crypto/tls, so the handler reads the
// connection state from the request context instead.
func Example_httpServer() {
	group, err := srptls.GroupByBits(3072)
	if err != nil {
		log.Fatal(err)
	}
	salt, err := srptls.NewSalt(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	stored, err := srptls.NewVerifier(group, []byte("device-1"), []byte("secret"), salt)
	if err != nil {
		log.Fatal(err)
	}
	// --8<-- [start:simulated]
	// The seed is a secret. Generate at least 16 random bytes once, store them
	// with the verifiers and use the same value on every instance and across
	// restarts.
	seed, err := hex.DecodeString(os.Getenv("SRP_SIMULATED_SEED"))
	if err != nil || len(seed) < 16 {
		log.Fatal("SRP_SIMULATED_SEED must hold at least 32 hexadecimal digits")
	}

	config := &srptls.Config{
		GetVerifier: func(info *srptls.ClientHelloInfo) (*srptls.Verifier, error) {
			if info.Username == "device-1" {
				return stored, nil
			}
			return srptls.SimulatedVerifier(seed, group, []byte(info.Username)), nil
		},
	}
	// --8<-- [end:simulated]
	// --8<-- [start:http-server]
	l, err := srptls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		// The handshake runs in the first read, so this also bounds it.
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			state := r.Context().Value(connKey{}).(*srptls.Conn).ConnectionState()
			fmt.Fprintf(w, "hello %s\n", state.SRPUsername)
		}),
	}
	go srv.Serve(l)
	defer srv.Close()
	// --8<-- [end:http-server]
}

// Example_httpClient sends an HTTPS request over TLS-SRP. The transport runs
// the handshake in DialTLSContext. net/http leaves Response.TLS nil for
// connections that are not crypto/tls, so the connection state, such as the
// tls-unique value an EST client puts in its CSR, comes from the Conn.
func Example_httpClient() {
	// --8<-- [start:http-client]
	config := &srptls.Config{
		Username:   "device-1",
		Password:   "secret",
		ServerName: "est.example",
	}
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := new(net.Dialer).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conn := srptls.Client(raw, config)
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				if errors.Is(err, srptls.ErrWrongPassword) {
					return nil, fmt.Errorf("wrong username or password: %w", err)
				}
				return nil, err
			}
			log.Printf("tls-unique %x", conn.ConnectionState().TLSUnique)
			return conn, nil
		},
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	resp, err := client.Get("https://est.example:8443/.well-known/est/cacerts")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	// --8<-- [end:http-client]
}
