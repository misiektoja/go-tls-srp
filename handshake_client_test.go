// Copyright 2026 The go-tls-srp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// testClientConfig returns a client Config with the credentials that
// testConfig knows.
func testClientConfig() *Config {
	return &Config{Username: testUser, Password: testPassword, ServerName: "est.example"}
}

// clientResult is the outcome of one handshake of Client against a server.
type clientResult struct {
	client    *Conn
	clientErr error
	serverErr error
}

// runClient runs the client handshake against serve, which runs the server
// side on its connection. A failed client only closes its write side, so
// that the server still reads the alert the client sent.
func runClient(t *testing.T, clientConfig *Config, serve func(net.Conn) error) clientResult {
	t.Helper()
	clientConn, serverConn := tcpPair(t)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serve(serverConn)
	}()
	client := Client(clientConn, clientConfig)
	clientErr := client.Handshake()
	if clientErr != nil {
		clientConn.(*net.TCPConn).CloseWrite()
	}
	return clientResult{client: client, clientErr: clientErr, serverErr: <-serverDone}
}

// runClientServer runs Client against Server and returns both ends.
func runClientServer(t *testing.T, serverConfig, clientConfig *Config) (clientResult, *Conn) {
	t.Helper()
	var server *Conn
	res := runClient(t, clientConfig, func(conn net.Conn) error {
		server = Server(conn, serverConfig)
		return server.Handshake()
	})
	return res, server
}

// checkSameState checks that both ends completed the handshake with the
// expected parameters and agree on tls-unique and exported keying material.
func checkSameState(t *testing.T, client, server *Conn, suite uint16, serverName string, ems bool) {
	t.Helper()
	cs, ss := client.ConnectionState(), server.ConnectionState()
	for side, s := range map[string]ConnectionState{"client": cs, "server": ss} {
		if !s.HandshakeComplete || s.Version != VersionTLS12 || s.CipherSuite != suite {
			t.Errorf("%s: complete %v, version %x, suite %s", side, s.HandshakeComplete, s.Version, CipherSuiteName(s.CipherSuite))
		}
		if s.ServerName != serverName || s.SRPUsername != testUser || s.ExtendedMasterSecret != ems {
			t.Errorf("%s: server name %q, username %q, EMS %v", side, s.ServerName, s.SRPUsername, s.ExtendedMasterSecret)
		}
	}
	if len(cs.TLSUnique) != finishedVerifyLength || !bytes.Equal(cs.TLSUnique, ss.TLSUnique) {
		t.Errorf("tls-unique: client %X, server %X", cs.TLSUnique, ss.TLSUnique)
	}
	if !ems {
		return
	}
	clientEKM, err := cs.ExportKeyingMaterial("EXPORTER-test", []byte("ctx"), 32)
	if err != nil {
		t.Fatal(err)
	}
	serverEKM, err := ss.ExportKeyingMaterial("EXPORTER-test", []byte("ctx"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientEKM, serverEKM) {
		t.Error("exported keying material differs between client and server")
	}
}

// TestClientHandshake runs Client against Server for every cipher suite and
// every group, with data in both directions. The 1024 and 1536 bit groups
// need MinGroupBits. Groups above 3072 bits are skipped with -short.
func TestClientHandshake(t *testing.T) {
	suites := []uint16{TLS_SRP_SHA_WITH_AES_256_CBC_SHA, TLS_SRP_SHA_WITH_AES_128_CBC_SHA, TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA}
	for _, group := range groups {
		if testing.Short() && group.Bits() > 3072 {
			continue
		}
		for _, suite := range suites {
			t.Run(fmt.Sprintf("%d/%s", group.Bits(), CipherSuiteName(suite)), func(t *testing.T) {
				t.Parallel()
				serverConfig := testConfig(t, group.Bits())
				serverConfig.CipherSuites = []uint16{suite}
				clientConfig := testClientConfig()
				clientConfig.CipherSuites = []uint16{suite}
				if group.Bits() < defaultMinGroupBits {
					clientConfig.MinGroupBits = group.Bits()
				}
				res, server := runClientServer(t, serverConfig, clientConfig)
				if res.clientErr != nil || res.serverErr != nil {
					t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
				}
				checkSameState(t, res.client, server, suite, "est.example", true)
				exchangeConnData(t, res.client, server)
			})
		}
	}
}

// TestClientCipherSuiteOrder checks the order in which the client offers
// cipher suites and that the server's preference decides.
func TestClientCipherSuiteOrder(t *testing.T) {
	tests := []struct {
		name    string
		config  []uint16
		offered []uint16
		chosen  uint16
	}{
		{"default", nil, []uint16{TLS_SRP_SHA_WITH_AES_256_CBC_SHA, TLS_SRP_SHA_WITH_AES_128_CBC_SHA}, TLS_SRP_SHA_WITH_AES_256_CBC_SHA},
		{"client order", []uint16{TLS_SRP_SHA_WITH_AES_128_CBC_SHA, TLS_SRP_SHA_WITH_AES_256_CBC_SHA}, []uint16{TLS_SRP_SHA_WITH_AES_128_CBC_SHA, TLS_SRP_SHA_WITH_AES_256_CBC_SHA}, TLS_SRP_SHA_WITH_AES_256_CBC_SHA},
		{"3DES listed", []uint16{TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA, TLS_SRP_SHA_WITH_AES_128_CBC_SHA}, []uint16{TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA, TLS_SRP_SHA_WITH_AES_128_CBC_SHA}, TLS_SRP_SHA_WITH_AES_128_CBC_SHA},
		{"unknown suites left out", []uint16{0xc02f, TLS_SRP_SHA_WITH_AES_128_CBC_SHA}, []uint16{TLS_SRP_SHA_WITH_AES_128_CBC_SHA}, TLS_SRP_SHA_WITH_AES_128_CBC_SHA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverConfig := testConfig(t, 2048)
			var offered []uint16
			next := serverConfig.GetVerifier
			serverConfig.GetVerifier = func(info *ClientHelloInfo) (*Verifier, error) {
				offered = info.CipherSuites
				return next(info)
			}
			clientConfig := testClientConfig()
			clientConfig.CipherSuites = tt.config
			res, server := runClientServer(t, serverConfig, clientConfig)
			if res.clientErr != nil || res.serverErr != nil {
				t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
			}
			if fmt.Sprint(offered) != fmt.Sprint(tt.offered) {
				t.Errorf("offered %x, want %x", offered, tt.offered)
			}
			checkSameState(t, res.client, server, tt.chosen, "est.example", true)
		})
	}
}

// TestClientServerName checks the SNI value the client sends and reports.
func TestClientServerName(t *testing.T) {
	tests := map[string]string{
		"":             "",
		"est.example":  "est.example",
		"est.example.": "est.example",
		"192.0.2.1":    "",
		"[2001:db8::]": "",
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			clientConfig := testClientConfig()
			clientConfig.ServerName = name
			res, server := runClientServer(t, testConfig(t, 2048), clientConfig)
			if res.clientErr != nil || res.serverErr != nil {
				t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
			}
			checkSameState(t, res.client, server, TLS_SRP_SHA_WITH_AES_256_CBC_SHA, want, true)
		})
	}
}

// TestClientFailures checks the errors of a client that the server refuses
// and of a client that refuses the server's group.
func TestClientFailures(t *testing.T) {
	tests := []struct {
		name   string
		bits   int
		config func(*Config)
		client func(*Config)
		// want is the sentinel error the client error must wrap, if any.
		want error
		// serverGot is the alert the server must receive from the client, if
		// the client refuses the server.
		serverGot alert
	}{
		{
			// RFC 5054, Section 2.6.
			name:   "wrong password",
			client: func(c *Config) { c.Password = "wrong" },
			want:   ErrWrongPassword,
		},
		{
			// RFC 5054, Section 2.5.1.3.
			name:   "unknown user with simulated verifier",
			client: func(c *Config) { c.Username = "ghost" },
			want:   ErrWrongPassword,
		},
		{
			name: "unknown user refused",
			config: func(c *Config) {
				c.GetVerifier = func(*ClientHelloInfo) (*Verifier, error) { return nil, ErrUnknownUsername }
			},
			want: ErrUnknownUsername,
		},
		{
			name: "access denied",
			config: func(c *Config) {
				c.GetVerifier = func(*ClientHelloInfo) (*Verifier, error) {
					return nil, fmt.Errorf("too many failed sign-ins: %w", ErrAccessDenied)
				}
			},
			want: ErrAccessDenied,
		},
		{
			// RFC 5054, Section 2.5.3.
			name:      "1024 bit group below the default minimum",
			bits:      1024,
			serverGot: alertInsufficientSecurity,
		},
		{
			name:      "1536 bit group below the default minimum",
			bits:      1536,
			serverGot: alertInsufficientSecurity,
		},
		{
			name:      "2048 bit group below a minimum of 3072",
			bits:      2048,
			client:    func(c *Config) { c.MinGroupBits = 3072 },
			serverGot: alertInsufficientSecurity,
		},
		{
			name:      "1024 bit group below a minimum of 1536",
			bits:      1024,
			client:    func(c *Config) { c.MinGroupBits = 1536 },
			serverGot: alertInsufficientSecurity,
		},
	}
	sentinels := []error{ErrWrongPassword, ErrUnknownUsername, ErrAccessDenied}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverConfig := testConfig(t, cmp.Or(tt.bits, 2048))
			if tt.config != nil {
				tt.config(serverConfig)
			}
			clientConfig := testClientConfig()
			if tt.client != nil {
				tt.client(clientConfig)
			}
			res, server := runClientServer(t, serverConfig, clientConfig)
			if res.clientErr == nil {
				t.Fatal("client handshake succeeded")
			}
			for _, sentinel := range sentinels {
				if got := errors.Is(res.clientErr, sentinel); got != (sentinel == tt.want) {
					t.Errorf("client error %q: errors.Is(%q) = %v", res.clientErr, sentinel, got)
				}
			}
			if tt.serverGot != 0 {
				if got, ok := remoteAlert(res.serverErr); !ok || got != tt.serverGot {
					t.Errorf("server error %v, want alert %v from the client", res.serverErr, tt.serverGot)
				}
			}
			if err := res.client.Handshake(); err != res.clientErr {
				t.Errorf("a later Handshake returned %v, want %v", err, res.clientErr)
			}
			if res.client.ConnectionState().HandshakeComplete || server.ConnectionState().HandshakeComplete {
				t.Error("a side reports a complete handshake")
			}
		})
	}
}

// TestClientConfigErrors checks that a client with an unusable Config fails
// before it sends anything.
func TestClientConfigErrors(t *testing.T) {
	long := strings.Repeat("u", 256)
	tests := map[string]*Config{
		"nil":                   nil,
		"no username":           {Password: testPassword},
		"long username":         {Username: long, Password: testPassword},
		"negative MinGroupBits": {Username: testUser, MinGroupBits: -1},
		"MinGroupBits too big":  {Username: testUser, MinGroupBits: 8193},
		"no SRP cipher suite":   {Username: testUser, CipherSuites: []uint16{0xc02f}},
		"empty cipher suites":   {Username: testUser, CipherSuites: []uint16{}},
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			res := runClient(t, config, func(conn net.Conn) error {
				sent, err := io.ReadAll(conn)
				if err == nil && len(sent) > 0 {
					err = fmt.Errorf("client sent %d bytes", len(sent))
				}
				return err
			})
			if res.clientErr == nil {
				t.Fatal("client handshake succeeded")
			}
			if res.serverErr != nil {
				t.Error(res.serverErr)
			}
			if _, err := res.client.Write([]byte("x")); err != res.clientErr {
				t.Errorf("Write returned %v, want the handshake error", err)
			}
			if _, err := res.client.Read(make([]byte, 1)); err != res.clientErr {
				t.Errorf("Read returned %v, want the handshake error", err)
			}
		})
	}
}

// TestClientKeyLogAndRand checks that the client draws its random from
// Config.Rand and logs the same master secret as the server.
func TestClientKeyLogAndRand(t *testing.T) {
	clientRandom := bytes.Repeat([]byte{0x5a}, 32)
	var clientLog, serverLog bytes.Buffer
	serverConfig := testConfig(t, 2048)
	serverConfig.KeyLogWriter = &serverLog
	clientConfig := testClientConfig()
	clientConfig.KeyLogWriter = &clientLog
	clientConfig.Rand = io.MultiReader(bytes.NewReader(clientRandom), rand.Reader)
	res, _ := runClientServer(t, serverConfig, clientConfig)
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
	}
	if prefix := fmt.Sprintf("CLIENT_RANDOM %x ", clientRandom); !strings.HasPrefix(clientLog.String(), prefix) {
		t.Errorf("client key log %q, want prefix %q", clientLog.String(), prefix)
	}
	if clientLog.String() != serverLog.String() {
		t.Errorf("client key log %q, server key log %q", clientLog.String(), serverLog.String())
	}
}

// fakeServerOptions describe how the fake server departs from a correct
// TLS-SRP server.
type fakeServerOptions struct {
	// bits is the group of the verifier, 2048 when zero.
	bits int
	// version is the ServerHello version, VersionTLS12 when zero.
	version uint16
	// cipherSuite is the chosen suite, the client's first when zero.
	cipherSuite uint16
	// noEMS leaves out Extended Master Secret.
	noEMS bool
	// renegotiation is sent as renegotiated_connection if not nil.
	renegotiation []byte
	// serverNameAck acknowledges SNI the client did not send.
	serverNameAck bool
	// extraExtension adds an ALPN extension the client never offers.
	extraExtension bool
	// n, g and serverPublic replace N, g and B in the ServerKeyExchange.
	n, g, serverPublic []byte
	// emptySalt sends an empty salt.
	emptySalt bool
	// tamperFinished alters the verify_data of the server's Finished.
	tamperFinished bool
	// impostor uses a verifier of another password and does not read the
	// client's Finished, like a server that does not hold the verifier.
	impostor bool
	// helloRequest sends a HelloRequest after the handshake.
	helloRequest bool
}

// fakeServer is a TLS-SRP server built on the package's record layer that
// can send altered messages.
type fakeServer struct {
	c              *Conn
	opts           fakeServerOptions
	clientHello    *clientHelloMsg
	transcript     finishedHash
	clientFinished []byte
}

// handshake runs the server side of a full SRP handshake with the
// departures in fs.opts.
func (fs *fakeServer) handshake() error {
	c := fs.c
	opts := fs.opts

	fs.transcript = newFinishedHash()
	hello := new(clientHelloMsg)
	if err := readRawMessage(c, &fs.transcript, typeClientHello, hello); err != nil {
		return err
	}
	fs.clientHello = hello
	c.vers = VersionTLS12
	// A client that refuses the version sends its alert in a TLS 1.0 record.
	c.haveVers = opts.version == 0

	group, err := GroupByBits(cmp.Or(opts.bits, 2048))
	if err != nil {
		return err
	}
	password := testPassword
	if opts.impostor {
		password = "not the password"
	}
	salt := []byte("fake server salt")
	verifier, err := NewVerifier(group, hello.srpUsername, []byte(password), salt)
	if err != nil {
		return err
	}
	srp, err := newSRPServer(verifier, rand.Reader)
	if err != nil {
		return err
	}

	serverHello := &serverHelloMsg{
		vers:                         cmp.Or(opts.version, VersionTLS12),
		random:                       make([]byte, 32),
		cipherSuite:                  cmp.Or(opts.cipherSuite, hello.cipherSuites[0]),
		secureRenegotiationSupported: hello.secureRenegotiationSupported || opts.renegotiation != nil,
		secureRenegotiation:          opts.renegotiation,
		extendedMasterSecret:         hello.extendedMasterSecret && !opts.noEMS,
		serverNameAck:                hello.serverName != "" || opts.serverNameAck,
	}
	rand.Read(serverHello.random)
	data, err := serverHello.marshal()
	if err != nil {
		return err
	}
	if opts.extraExtension {
		data = withServerHelloExtension(data, 16, []byte{0, 3, 2, 'h', '2'})
	}
	if _, err := c.writeHandshakeRecord(rawMessage(data), &fs.transcript); err != nil {
		return err
	}

	n, g, serverPublic := group.N(), group.Generator(), srp.public
	if opts.n != nil {
		n = opts.n
	}
	if opts.g != nil {
		g = opts.g
	}
	if opts.serverPublic != nil {
		serverPublic = opts.serverPublic
	}
	if opts.emptySalt {
		salt = nil
	}
	skx := &serverKeyExchangeMsg{key: rawSRPParams(n, g, salt, serverPublic)}
	if _, err := c.writeHandshakeRecord(skx, &fs.transcript); err != nil {
		return err
	}
	if _, err := c.writeHandshakeRecord(new(serverHelloDoneMsg), &fs.transcript); err != nil {
		return err
	}

	ckx := new(clientKeyExchangeMsg)
	if err := readRawMessage(c, &fs.transcript, typeClientKeyExchange, ckx); err != nil {
		return err
	}
	clientPublic, ok := srpClientPublic(ckx.ciphertext)
	if !ok {
		return errors.New("malformed ClientKeyExchange")
	}
	premaster, err := srp.premasterSecret(clientPublic)
	if err != nil {
		return err
	}
	var masterSecret []byte
	if serverHello.extendedMasterSecret {
		masterSecret = extMasterFromPreMasterSecret(premaster, fs.transcript.Sum())
	} else {
		masterSecret = masterFromPreMasterSecret(premaster, hello.random, serverHello.random)
	}
	suite := cipherSuiteByID(serverHello.cipherSuite)
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(masterSecret, hello.random, serverHello.random, suite.macLen, suite.keyLen, suite.ivLen)
	c.in.prepareCipherSpec(suite.cipher(clientKey, clientIV, true), suite.mac(clientMAC))
	c.out.prepareCipherSpec(suite.cipher(serverKey, serverIV, false), suite.mac(serverMAC))

	if !opts.impostor {
		if err := c.readChangeCipherSpec(); err != nil {
			return err
		}
		want := fs.transcript.clientSum(masterSecret)
		finished := new(finishedMsg)
		if err := readRawMessage(c, &fs.transcript, typeFinished, finished); err != nil {
			return err
		}
		if !bytes.Equal(finished.verifyData, want) {
			return errors.New("client Finished is incorrect")
		}
		fs.clientFinished = finished.verifyData
	}

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}
	verifyData := fs.transcript.serverSum(masterSecret)
	if opts.tamperFinished {
		verifyData[0] ^= 1
	}
	if _, err := c.writeHandshakeRecord(&finishedMsg{verifyData: verifyData}, &fs.transcript); err != nil {
		return err
	}
	c.isHandshakeComplete.Store(true)

	if opts.helloRequest {
		if _, err := c.writeHandshakeRecord(new(helloRequestMsg), nil); err != nil {
			return err
		}
	}
	return nil
}

// runFakeServer runs Client against a fake server with the given options.
func runFakeServer(t *testing.T, opts fakeServerOptions, clientConfig *Config) (clientResult, *fakeServer) {
	t.Helper()
	var fs *fakeServer
	res := runClient(t, clientConfig, func(conn net.Conn) error {
		fs = &fakeServer{c: &Conn{conn: conn, config: &Config{}}, opts: opts}
		return fs.handshake()
	})
	return res, fs
}

// rawMessage is a handshake message in its wire form.
type rawMessage []byte

// marshal returns the message as given.
func (m rawMessage) marshal() ([]byte, error) { return m, nil }

// unmarshal is not supported.
func (m rawMessage) unmarshal([]byte) bool { return false }

// rawSRPParams encodes ServerSRPParams with the values exactly as given.
func rawSRPParams(n, g, salt, b []byte) []byte {
	var params cryptobyte.Builder
	params.AddUint16LengthPrefixed(func(p *cryptobyte.Builder) { p.AddBytes(n) })
	params.AddUint16LengthPrefixed(func(p *cryptobyte.Builder) { p.AddBytes(g) })
	params.AddUint8LengthPrefixed(func(p *cryptobyte.Builder) { p.AddBytes(salt) })
	params.AddUint16LengthPrefixed(func(p *cryptobyte.Builder) { p.AddBytes(b) })
	return params.BytesOrPanic()
}

// withServerHelloExtension appends an extension to a marshaled ServerHello
// that already has extensions and fixes both length fields.
func withServerHelloExtension(data []byte, typ uint16, body []byte) []byte {
	var ext cryptobyte.Builder
	ext.AddUint16(typ)
	ext.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body) })
	out := append(append([]byte(nil), data...), ext.BytesOrPanic()...)
	n := len(out) - 4
	out[1], out[2], out[3] = byte(n>>16), byte(n>>8), byte(n)
	// type, length, version, random, session ID, cipher suite, compression
	off := 4 + 2 + 32 + 1 + int(out[38]) + 2 + 1
	l := len(out) - off - 2
	out[off], out[off+1] = byte(l>>8), byte(l)
	return out
}

// TestClientHello checks the ClientHello the client sends.
func TestClientHello(t *testing.T) {
	res, fs := runFakeServer(t, fakeServerOptions{}, testClientConfig())
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
	}
	hello := fs.clientHello
	if hello.vers != VersionTLS12 || len(hello.sessionId) != 0 || !bytes.Equal(hello.compressionMethods, []uint8{compressionNone}) {
		t.Errorf("version %x, session ID %X, compression %v", hello.vers, hello.sessionId, hello.compressionMethods)
	}
	if string(hello.srpUsername) != testUser || hello.serverName != "est.example" {
		t.Errorf("username %q, server name %q", hello.srpUsername, hello.serverName)
	}
	// RFC 7627 and RFC 5746, Section 3.4: the extension, not the SCSV.
	if !hello.extendedMasterSecret || !hello.secureRenegotiationSupported || len(hello.secureRenegotiation) != 0 {
		t.Errorf("EMS %v, renegotiation_info %v %X", hello.extendedMasterSecret, hello.secureRenegotiationSupported, hello.secureRenegotiation)
	}
	for _, id := range hello.cipherSuites {
		if id == scsvRenegotiation {
			t.Error("client sent the renegotiation SCSV")
		}
	}
	if !bytes.Equal(res.client.ConnectionState().TLSUnique, fs.clientFinished) {
		t.Error("client tls-unique differs from the Finished message the server received")
	}
}

// TestClientWithoutEMS checks a handshake with a server that does not
// support Extended Master Secret, which Server always does.
func TestClientWithoutEMS(t *testing.T) {
	res, fs := runFakeServer(t, fakeServerOptions{noEMS: true}, testClientConfig())
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
	}
	state := res.client.ConnectionState()
	if !state.HandshakeComplete || state.ExtendedMasterSecret {
		t.Errorf("complete %v, EMS %v", state.HandshakeComplete, state.ExtendedMasterSecret)
	}
	if !bytes.Equal(state.TLSUnique, fs.clientFinished) {
		t.Errorf("tls-unique %X, Finished received by the server %X", state.TLSUnique, fs.clientFinished)
	}
	if _, err := state.ExportKeyingMaterial("EXPORTER-test", nil, 32); err == nil {
		t.Error("ExportKeyingMaterial succeeded without EMS")
	}
	exchangeConnData(t, res.client, fs.c)
}

// TestClientRefusesServer checks that the client refuses a server that
// breaks the protocol or cannot prove that it holds the verifier.
func TestClientRefusesServer(t *testing.T) {
	group, _ := GroupByBits(2048)
	n := new(big.Int).SetBytes(group.N())
	nPlus := func(k int64) []byte { return new(big.Int).Add(n, big.NewInt(k)).Bytes() }
	tests := []struct {
		name string
		opts fakeServerOptions
		// serverGot is the alert the server receives, or zero if the server
		// does not read it.
		serverGot alert
		// clientSent is the alert the client error carries, if any.
		clientSent alert
		// cause is an error the client error must wrap, if any.
		cause error
	}{
		{
			// RFC 5054, Section 2.5.3.
			name:      "prime outside RFC 5054",
			opts:      fakeServerOptions{n: nPlus(2)},
			serverGot: alertInsufficientSecurity,
		},
		{
			name:      "RFC 5054 prime with another generator",
			opts:      fakeServerOptions{g: []byte{5}},
			serverGot: alertInsufficientSecurity,
		},
		{
			// RFC 5054, Section 2.5.3: B % N = 0.
			name:      "B is zero",
			opts:      fakeServerOptions{serverPublic: []byte{0}},
			serverGot: alertIllegalParameter,
			cause:     errBadServerPublic,
		},
		{
			name:      "B is N",
			opts:      fakeServerOptions{serverPublic: group.N()},
			serverGot: alertIllegalParameter,
			cause:     errBadServerPublic,
		},
		{
			name:      "B is 2N",
			opts:      fakeServerOptions{serverPublic: new(big.Int).Lsh(n, 1).Bytes()},
			serverGot: alertIllegalParameter,
			cause:     errBadServerPublic,
		},
		{
			name:      "B is above N",
			opts:      fakeServerOptions{serverPublic: nPlus(1)},
			serverGot: alertIllegalParameter,
			cause:     errBadServerPublic,
		},
		{
			// RFC 5054, Section 2.8.2: opaque srp_s<1..2^8-1>.
			name:      "empty salt",
			opts:      fakeServerOptions{emptySalt: true},
			serverGot: alertDecodeError,
		},
		{
			name:      "TLS 1.1",
			opts:      fakeServerOptions{version: VersionTLS11},
			serverGot: alertProtocolVersion,
		},
		{
			name:      "TLS 1.3 version number",
			opts:      fakeServerOptions{version: 0x0304},
			serverGot: alertProtocolVersion,
		},
		{
			name:      "cipher suite not offered",
			opts:      fakeServerOptions{cipherSuite: TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA},
			serverGot: alertIllegalParameter,
		},
		{
			// RFC 5746, Section 3.4.
			name:      "renegotiation data in the initial handshake",
			opts:      fakeServerOptions{renegotiation: []byte{1, 2, 3}},
			serverGot: alertHandshakeFailure,
		},
		{
			name:      "extension not offered",
			opts:      fakeServerOptions{extraExtension: true},
			serverGot: alertUnsupportedExtension,
		},
		{
			name:      "group of the RFC 5054 Appendix A below the minimum",
			opts:      fakeServerOptions{bits: 1536},
			serverGot: alertInsufficientSecurity,
		},
		{
			name:      "tampered Finished",
			opts:      fakeServerOptions{tamperFinished: true},
			serverGot: alertHandshakeFailure,
			cause:     errServerFinished,
		},
		{
			name:       "server without the verifier",
			opts:       fakeServerOptions{impostor: true},
			clientSent: alertBadRecordMAC,
		},
	}
	sentinels := []error{ErrWrongPassword, ErrUnknownUsername, ErrAccessDenied}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, fs := runFakeServer(t, tt.opts, testClientConfig())
			if res.clientErr == nil {
				t.Fatal("client handshake succeeded")
			}
			for _, sentinel := range sentinels {
				if errors.Is(res.clientErr, sentinel) {
					t.Errorf("client error %q wraps %q", res.clientErr, sentinel)
				}
			}
			if tt.cause != nil && !errors.Is(res.clientErr, tt.cause) {
				t.Errorf("client error %q does not wrap %q", res.clientErr, tt.cause)
			}
			if tt.clientSent != 0 {
				if got, ok := localAlert(res.clientErr); !ok || got != tt.clientSent {
					t.Errorf("client error %v, want local alert %v", res.clientErr, tt.clientSent)
				}
			}
			if tt.serverGot != 0 {
				serverErr := res.serverErr
				if serverErr == nil {
					// The fake server finished its side, so the alert
					// follows its Finished message.
					_, serverErr = fs.c.Read(make([]byte, 1))
				}
				if got, ok := remoteAlert(serverErr); !ok || got != tt.serverGot {
					t.Errorf("server error %v, want alert %v from the client", serverErr, tt.serverGot)
				}
			}
			if res.client.ConnectionState().HandshakeComplete {
				t.Error("client reports a complete handshake")
			}
		})
	}
}

// TestClientRefusesSNIAck checks that the client refuses a server_name
// acknowledgement when it sent no SNI.
func TestClientRefusesSNIAck(t *testing.T) {
	clientConfig := testClientConfig()
	clientConfig.ServerName = ""
	res, _ := runFakeServer(t, fakeServerOptions{serverNameAck: true}, clientConfig)
	if res.clientErr == nil {
		t.Fatal("client handshake succeeded")
	}
	if got, ok := remoteAlert(res.serverErr); !ok || got != alertUnsupportedExtension {
		t.Errorf("server error %v, want unsupported_extension", res.serverErr)
	}
}

// TestClientRenegotiationRefused checks that a HelloRequest after the
// handshake fails the client's Read with a no_renegotiation warning.
func TestClientRenegotiationRefused(t *testing.T) {
	res, _ := runFakeServer(t, fakeServerOptions{helloRequest: true}, testClientConfig())
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
	}
	_, err := res.client.Read(make([]byte, 1))
	if got, ok := localAlert(err); !ok || got != alertNoRenegotiation {
		t.Fatalf("Read returned %v, want local no_renegotiation", err)
	}
	if _, err := res.client.Write([]byte("x")); err == nil {
		t.Error("Write succeeded after a refused renegotiation")
	}
}

// TestClientWithNetHTTP checks the documented net/http setup: the client
// handshake in Transport.DialTLSContext against an http.Server on Listen.
func TestClientWithNetHTTP(t *testing.T) {
	type connKey struct{}
	l, err := Listen("tcp", "127.0.0.1:0", testConfig(t, 2048))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			state := r.Context().Value(connKey{}).(*Conn).ConnectionState()
			fmt.Fprintf(w, "%s %X", state.SRPUsername, state.TLSUnique)
		}),
	}
	go srv.Serve(l)
	defer srv.Close()

	var tlsUnique []byte
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := new(net.Dialer).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conn := Client(raw, testClientConfig())
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			tlsUnique = conn.ConnectionState().TLSUnique
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	resp, err := client.Get("https://" + l.Addr().String() + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%s %X", testUser, tlsUnique); string(body) != want || resp.TLS != nil {
		t.Errorf("body %q, want %q; Response.TLS %v", body, want, resp.TLS)
	}
}
