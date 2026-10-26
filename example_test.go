// Copyright 2026 The go-tls-srp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	srptls "github.com/misiektoja/go-tls-srp"
)

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
}

// Example_httpClient sends an HTTPS request over TLS-SRP. The transport runs
// the handshake in DialTLSContext. net/http leaves Response.TLS nil for
// connections that are not crypto/tls, so the connection state, such as the
// tls-unique value an EST client puts in its CSR, comes from the Conn.
func Example_httpClient() {
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
}
