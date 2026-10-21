// Copyright 2026 The go-tls-srp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// testUser and testPassword are the credentials the test server knows.
const (
	testUser     = "device-1"
	testPassword = "secret-1"
)

// clientOptions describe the ClientHello and behavior of the test client.
type clientOptions struct {
	username        string
	password        string
	version         uint16
	cipherSuites    []uint16
	noSRPExtension  bool
	noEMS           bool
	renegotiation   []byte
	scsv            bool
	serverName      string
	overridePublicA []byte
}

// defaultClientOptions mirrors a libest client: TLS 1.2, AES-256 first and
// Extended Master Secret.
func defaultClientOptions() clientOptions {
	return clientOptions{
		username:     testUser,
		password:     testPassword,
		version:      VersionTLS12,
		cipherSuites: []uint16{TLS_SRP_SHA_WITH_AES_256_CBC_SHA, TLS_SRP_SHA_WITH_AES_128_CBC_SHA, TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA},
		scsv:         true,
	}
}

// testClient is a minimal TLS-SRP client built on the package's record layer.
type testClient struct {
	c            *Conn
	opts         clientOptions
	clientRandom []byte
	serverHello  *serverHelloMsg
	transcript   finishedHash
	masterSecret []byte
	finished     []byte
}

// handshake runs the client side of a full SRP handshake.
func (tc *testClient) handshake() error {
	c := tc.c
	opts := tc.opts
	tc.clientRandom = make([]byte, 32)
	rand.Read(tc.clientRandom)

	suites := append([]uint16(nil), opts.cipherSuites...)
	if opts.scsv {
		suites = append(suites, scsvRenegotiation)
	}
	hello := &clientHelloMsg{
		vers:                         opts.version,
		random:                       tc.clientRandom,
		cipherSuites:                 suites,
		compressionMethods:           []uint8{compressionNone},
		serverName:                   opts.serverName,
		extendedMasterSecret:         !opts.noEMS,
		secureRenegotiationSupported: opts.renegotiation != nil,
		secureRenegotiation:          opts.renegotiation,
	}
	if !opts.noSRPExtension {
		hello.srpUsername = []byte(opts.username)
	}
	tc.transcript = newFinishedHash()
	if _, err := c.writeHandshakeRecord(hello, &tc.transcript); err != nil {
		return err
	}

	serverHello := new(serverHelloMsg)
	if err := tc.readMessage(typeServerHello, serverHello); err != nil {
		return err
	}
	tc.serverHello = serverHello
	c.vers = serverHello.vers
	c.haveVers = true

	skx := new(serverKeyExchangeMsg)
	if err := tc.readMessage(typeServerKeyExchange, skx); err != nil {
		return err
	}
	if err := tc.readMessage(typeServerHelloDone, new(serverHelloDoneMsg)); err != nil {
		return err
	}

	n, g, salt, serverB, err := parseSRPParams(skx.key)
	if err != nil {
		return err
	}
	group, err := GroupByParameters(n, g)
	if err != nil {
		return err
	}
	a := make([]byte, 32)
	rand.Read(a)
	srp := srpClientPremaster(group, a, serverB, salt, []byte(opts.username), []byte(opts.password))
	clientA := srp.public
	if opts.overridePublicA != nil {
		clientA = opts.overridePublicA
	}
	var body cryptobyte.Builder
	body.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(clientA) })
	ckx := &clientKeyExchangeMsg{ciphertext: body.BytesOrPanic()}
	if _, err := c.writeHandshakeRecord(ckx, &tc.transcript); err != nil {
		return err
	}

	if serverHello.extendedMasterSecret {
		tc.masterSecret = extMasterFromPreMasterSecret(srp.premaster, tc.transcript.Sum())
	} else {
		tc.masterSecret = masterFromPreMasterSecret(srp.premaster, tc.clientRandom, serverHello.random)
	}
	suite := cipherSuiteByID(serverHello.cipherSuite)
	if suite == nil {
		return fmt.Errorf("server chose unknown suite %x", serverHello.cipherSuite)
	}
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(tc.masterSecret, tc.clientRandom, serverHello.random, suite.macLen, suite.keyLen, suite.ivLen)
	c.out.prepareCipherSpec(suite.cipher(clientKey, clientIV, false), suite.mac(clientMAC))
	c.in.prepareCipherSpec(suite.cipher(serverKey, serverIV, true), suite.mac(serverMAC))

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}
	tc.finished = tc.transcript.clientSum(tc.masterSecret)
	if _, err := c.writeHandshakeRecord(&finishedMsg{verifyData: tc.finished}, &tc.transcript); err != nil {
		return err
	}

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}
	want := tc.transcript.serverSum(tc.masterSecret)
	serverFinished := new(finishedMsg)
	if err := tc.readMessage(typeFinished, serverFinished); err != nil {
		return err
	}
	if !bytes.Equal(serverFinished.verifyData, want) {
		return errors.New("server Finished is incorrect")
	}
	c.isHandshakeComplete.Store(true)
	return nil
}

// readMessage reads one handshake message of the given type into m and adds
// it to the transcript.
func (tc *testClient) readMessage(typ uint8, m handshakeMessage) error {
	return readRawMessage(tc.c, &tc.transcript, typ, m)
}

// readRawMessage reads one handshake message of the given type from c into m
// and adds it to transcript. Unlike readHandshake it accepts every message
// type, so that the test peers can read the messages of either side.
func readRawMessage(c *Conn, transcript *finishedHash, typ uint8, m handshakeMessage) error {
	if err := c.readHandshakeBytes(4); err != nil {
		return err
	}
	data := c.hand.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if err := c.readHandshakeBytes(4 + n); err != nil {
		return err
	}
	data = append([]byte(nil), c.hand.Next(4+n)...)
	if data[0] != typ {
		return fmt.Errorf("got handshake message %d, want %d", data[0], typ)
	}
	if !m.unmarshal(data) {
		return fmt.Errorf("cannot parse handshake message %d", typ)
	}
	transcript.Write(data)
	return nil
}

// parseSRPParams decodes ServerSRPParams from RFC 5054, Section 2.8.2.
func parseSRPParams(body []byte) (n, g, salt, b []byte, err error) {
	s := cryptobyte.String(body)
	if !readUint16LengthPrefixed(&s, &n) || !readUint16LengthPrefixed(&s, &g) ||
		!readUint8LengthPrefixed(&s, &salt) || !readUint16LengthPrefixed(&s, &b) || !s.Empty() {
		return nil, nil, nil, nil, errors.New("malformed ServerSRPParams")
	}
	return n, g, salt, b, nil
}

// testConfig returns a server Config that knows testUser in the given group.
func testConfig(t testing.TB, bits int) *Config {
	t.Helper()
	group, err := GroupByBits(bits)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := NewSalt(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(group, []byte(testUser), []byte(testPassword), salt)
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte("simulated verifier seed for tests")
	return &Config{
		GetVerifier: func(info *ClientHelloInfo) (*Verifier, error) {
			if info.Username == testUser {
				return verifier, nil
			}
			return SimulatedVerifier(seed, group, []byte(info.Username)), nil
		},
	}
}

// handshakeResult is the outcome of one test handshake on both sides.
type handshakeResult struct {
	client    *testClient
	server    *Conn
	clientErr error
	serverErr error
}

// tcpPair returns both ends of a loopback TCP connection. TCP rather than
// net.Pipe, because a failing server writes its alert while the client is
// still writing, which deadlocks an unbuffered pipe.
func tcpPair(t testing.TB) (client, server net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	deadline := time.Now().Add(30 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

// runHandshake connects the test client to a server over loopback TCP.
func runHandshake(t *testing.T, config *Config, opts clientOptions) handshakeResult {
	t.Helper()
	clientConn, serverConn := tcpPair(t)

	server := Server(serverConn, config)
	serverDone := make(chan error, 1)
	go func() {
		err := server.Handshake()
		serverDone <- err
		if err != nil {
			// Read until the client closes. Closing a socket with unread
			// data sends a reset, which can discard the alert before the
			// client reads it.
			io.Copy(io.Discard, serverConn)
		}
	}()

	client := &testClient{c: &Conn{conn: clientConn, config: &Config{}}, opts: opts}
	clientErr := client.handshake()
	if clientErr != nil {
		clientConn.Close()
	}
	return handshakeResult{client: client, server: server, clientErr: clientErr, serverErr: <-serverDone}
}

// remoteAlert returns the alert in an error the client received from the
// server, or false.
func remoteAlert(err error) (alert, bool) {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" {
		a, ok := opErr.Err.(alert)
		return a, ok
	}
	return 0, false
}

// localAlert returns the alert the server sent, or false.
func localAlert(err error) (alert, bool) {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "local error" {
		a, ok := opErr.Err.(alert)
		return a, ok
	}
	return 0, false
}

// TestHandshake checks a successful handshake, the connection state, the
// exported keying material and data in both directions.
func TestHandshake(t *testing.T) {
	opts := defaultClientOptions()
	opts.serverName = "est.example"
	res := runHandshake(t, testConfig(t, 3072), opts)
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
	}

	state := res.server.ConnectionState()
	if !state.HandshakeComplete || state.Version != VersionTLS12 || state.CipherSuite != TLS_SRP_SHA_WITH_AES_256_CBC_SHA {
		t.Errorf("state = %+v", state)
	}
	if state.SRPUsername != testUser || state.ServerName != "est.example" || !state.ExtendedMasterSecret {
		t.Errorf("username %q, server name %q, EMS %v", state.SRPUsername, state.ServerName, state.ExtendedMasterSecret)
	}
	if !bytes.Equal(state.TLSUnique, res.client.finished) {
		t.Errorf("tls-unique %X, client Finished %X", state.TLSUnique, res.client.finished)
	}
	sh := res.client.serverHello
	if !sh.secureRenegotiationSupported || len(sh.secureRenegotiation) != 0 || !sh.extendedMasterSecret || !sh.serverNameAck {
		t.Errorf("ServerHello extensions = %+v", sh)
	}

	ekm, err := state.ExportKeyingMaterial("EXPORTER-test", []byte("ctx"), 32)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ekmFromMasterSecret(res.client.masterSecret, res.client.clientRandom, sh.random)("EXPORTER-test", []byte("ctx"), 32)
	if !bytes.Equal(ekm, want) {
		t.Error("exported keying material differs between client and server")
	}

	exchangeData(t, res)
}

// exchangeData sends application data in both directions, including a
// record larger than the first small records.
func exchangeData(t *testing.T, res handshakeResult) {
	t.Helper()
	exchangeConnData(t, res.client.c, res.server)
}

// exchangeConnData sends a request from client to server and a response
// back. The request is larger than the first small records.
func exchangeConnData(t *testing.T, client, server *Conn) {
	t.Helper()
	request := bytes.Repeat([]byte("GET /.well-known/est/cacerts "), 1000)
	response := []byte("HTTP/1.1 200 OK")

	errc := make(chan error, 1)
	go func() {
		got := make([]byte, len(request))
		if _, err := io.ReadFull(server, got); err != nil {
			errc <- err
			return
		}
		if !bytes.Equal(got, request) {
			errc <- errors.New("server read different data")
			return
		}
		_, err := server.Write(response)
		errc <- err
	}()
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Errorf("client read %q", got)
	}
}

// TestHandshakeCipherSuites checks the default preference order and that
// 3DES is used only when configured.
func TestHandshakeCipherSuites(t *testing.T) {
	tests := []struct {
		name   string
		server []uint16
		client []uint16
		want   uint16
	}{
		{"client prefers AES-128", nil, []uint16{TLS_SRP_SHA_WITH_AES_128_CBC_SHA, TLS_SRP_SHA_WITH_AES_256_CBC_SHA}, TLS_SRP_SHA_WITH_AES_256_CBC_SHA},
		{"AES-128 only", nil, []uint16{TLS_SRP_SHA_WITH_AES_128_CBC_SHA}, TLS_SRP_SHA_WITH_AES_128_CBC_SHA},
		{"3DES configured", []uint16{TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA}, []uint16{TLS_SRP_SHA_WITH_AES_256_CBC_SHA, TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA}, TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig(t, 1024)
			config.CipherSuites = tt.server
			opts := defaultClientOptions()
			opts.cipherSuites = tt.client
			res := runHandshake(t, config, opts)
			if res.clientErr != nil || res.serverErr != nil {
				t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
			}
			if got := res.server.ConnectionState().CipherSuite; got != tt.want {
				t.Errorf("suite = %s, want %s", CipherSuiteName(got), CipherSuiteName(tt.want))
			}
			exchangeData(t, res)
		})
	}
}

// TestHandshakeWithoutEMS checks a client without Extended Master Secret and
// that exporting keying material is then refused.
func TestHandshakeWithoutEMS(t *testing.T) {
	opts := defaultClientOptions()
	opts.noEMS = true
	opts.scsv = false
	opts.renegotiation = []byte{}
	res := runHandshake(t, testConfig(t, 2048), opts)
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
	}
	state := res.server.ConnectionState()
	if state.ExtendedMasterSecret || res.client.serverHello.extendedMasterSecret {
		t.Error("EMS negotiated without the client asking")
	}
	if _, err := state.ExportKeyingMaterial("EXPORTER-test", nil, 32); err == nil {
		t.Error("ExportKeyingMaterial succeeded without EMS")
	}
	exchangeData(t, res)
}

// TestHandshakeGroups runs a handshake in every RFC 5054 group. Groups above
// 3072 bits are skipped with -short.
func TestHandshakeGroups(t *testing.T) {
	for _, group := range groups {
		if testing.Short() && group.Bits() > 3072 {
			continue
		}
		t.Run(fmt.Sprint(group.Bits()), func(t *testing.T) {
			res := runHandshake(t, testConfig(t, group.Bits()), defaultClientOptions())
			if res.clientErr != nil || res.serverErr != nil {
				t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
			}
		})
	}
}

// TestHandshakeFailures checks the alert the server sends for each kind of
// refused client.
func TestHandshakeFailures(t *testing.T) {
	group, _ := GroupByBits(1024)
	tests := []struct {
		name   string
		config func(*Config)
		opts   func(*clientOptions)
		want   alert
		// wrongPassword is whether the server error wraps ErrWrongPassword.
		wrongPassword bool
		// cause is an error the server error must wrap, if any.
		cause error
	}{
		{
			// RFC 5054, Section 2.6: a wrong password shows as a bad MAC.
			name:          "wrong password",
			opts:          func(o *clientOptions) { o.password = "wrong" },
			want:          alertBadRecordMAC,
			wrongPassword: true,
		},
		{
			// RFC 5054, Section 2.5.1.3: an unknown user looks the same.
			name:          "unknown user with simulated verifier",
			opts:          func(o *clientOptions) { o.username = "ghost" },
			want:          alertBadRecordMAC,
			wrongPassword: true,
		},
		{
			name: "refused by GetVerifier",
			config: func(c *Config) {
				c.GetVerifier = func(*ClientHelloInfo) (*Verifier, error) {
					return nil, fmt.Errorf("too many failed sign-ins: %w", ErrAccessDenied)
				}
			},
			want:  alertAccessDenied,
			cause: ErrAccessDenied,
		},
		{
			name: "unknown user refused",
			config: func(c *Config) {
				next := c.GetVerifier
				c.GetVerifier = func(info *ClientHelloInfo) (*Verifier, error) {
					if info.Username != testUser {
						return nil, ErrUnknownUsername
					}
					return next(info)
				}
			},
			opts: func(o *clientOptions) { o.username = "ghost" },
			want: alertUnknownPSKIdentity,
		},
		{
			name: "lookup error",
			config: func(c *Config) {
				c.GetVerifier = func(*ClientHelloInfo) (*Verifier, error) { return nil, errors.New("database down") }
			},
			want: alertInternalError,
		},
		{
			name: "invalid stored verifier",
			config: func(c *Config) {
				c.GetVerifier = func(*ClientHelloInfo) (*Verifier, error) {
					return &Verifier{Group: group, Salt: []byte{1}, Value: group.N()}, nil
				}
			},
			want: alertInternalError,
		},
		{
			// RFC 5054, Section 2.5.1.2.
			name: "no SRP extension",
			opts: func(o *clientOptions) { o.noSRPExtension = true },
			want: alertUnknownPSKIdentity,
		},
		{
			name: "TLS 1.1 client",
			opts: func(o *clientOptions) { o.version = VersionTLS11 },
			want: alertProtocolVersion,
		},
		{
			name: "no SRP cipher suite",
			opts: func(o *clientOptions) { o.cipherSuites = []uint16{0xc02f, 0x009c} },
			want: alertHandshakeFailure,
		},
		{
			name: "3DES not configured",
			opts: func(o *clientOptions) { o.cipherSuites = []uint16{TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA} },
			want: alertHandshakeFailure,
		},
		{
			name: "renegotiation data in the initial handshake",
			opts: func(o *clientOptions) { o.renegotiation = []byte{1, 2, 3} },
			want: alertHandshakeFailure,
		},
		{
			// RFC 5054, Section 2.5.4.
			name: "A is zero",
			opts: func(o *clientOptions) { o.overridePublicA = []byte{0} },
			want: alertIllegalParameter,
		},
		{
			name: "A is N",
			opts: func(o *clientOptions) { o.overridePublicA = group.N() },
			want: alertIllegalParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig(t, 1024)
			if tt.config != nil {
				tt.config(config)
			}
			opts := defaultClientOptions()
			if tt.opts != nil {
				tt.opts(&opts)
			}
			res := runHandshake(t, config, opts)
			if res.serverErr == nil {
				t.Fatal("server handshake succeeded")
			}
			if got, ok := remoteAlert(res.clientErr); !ok || got != tt.want {
				t.Errorf("client got %v, want alert %v", res.clientErr, tt.want)
			}
			if got := errors.Is(res.serverErr, ErrWrongPassword); got != tt.wrongPassword {
				t.Errorf("server error %v: wraps ErrWrongPassword = %v, want %v", res.serverErr, got, tt.wrongPassword)
			}
			if tt.cause != nil && !errors.Is(res.serverErr, tt.cause) {
				t.Errorf("server error %v does not wrap %v", res.serverErr, tt.cause)
			}
			if err := res.server.Handshake(); !errors.Is(err, ErrWrongPassword) && tt.wrongPassword {
				t.Errorf("a later Handshake returned %v, want the same wrong password error", err)
			}
			if res.server.ConnectionState().HandshakeComplete {
				t.Error("server reports a complete handshake")
			}
		})
	}
}

// TestRenegotiationRefused checks that a ClientHello after the handshake
// ends the connection.
func TestRenegotiationRefused(t *testing.T) {
	res := runHandshake(t, testConfig(t, 1024), defaultClientOptions())
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("client: %v, server: %v", res.clientErr, res.serverErr)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := res.server.Read(make([]byte, 1))
		errc <- err
	}()
	hello := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{TLS_SRP_SHA_WITH_AES_256_CBC_SHA},
		compressionMethods: []uint8{compressionNone},
		srpUsername:        []byte(testUser),
	}
	if _, err := res.client.c.writeHandshakeRecord(hello, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err == nil {
		t.Fatal("server accepted a renegotiation")
	}
	if _, err := res.client.c.Read(make([]byte, 1)); err == nil {
		t.Fatal("client read data after renegotiation")
	} else if got, ok := remoteAlert(err); !ok || got != alertUnexpectedMessage {
		t.Errorf("client got %v, want unexpected_message", err)
	}
}

// TestNotTLS checks that plain HTTP on the TLS port fails before the server
// reads a full record.
func TestNotTLS(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	server := Server(serverConn, testConfig(t, 1024))
	go clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: est\r\n\r\n"))
	err := server.Handshake()
	var headerErr RecordHeaderError
	if !errors.As(err, &headerErr) || headerErr.Conn == nil {
		t.Fatalf("err = %v, want RecordHeaderError with the connection", err)
	}
}

// TestMissingGetVerifier checks that a Config without GetVerifier fails.
func TestMissingGetVerifier(t *testing.T) {
	if _, err := Listen("tcp", "127.0.0.1:0", &Config{}); err == nil {
		t.Error("Listen accepted a Config without GetVerifier")
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go io.Copy(io.Discard, clientConn)
	if err := Server(serverConn, &Config{}).Handshake(); err == nil {
		t.Error("handshake succeeded without GetVerifier")
	}
}

// TestLocalAlertOnServer checks that the server reports the alert it sent.
func TestLocalAlertOnServer(t *testing.T) {
	opts := defaultClientOptions()
	opts.password = "wrong"
	res := runHandshake(t, testConfig(t, 1024), opts)
	if got, ok := localAlert(res.serverErr); !ok || got != alertBadRecordMAC {
		t.Errorf("server error = %v, want local bad_record_mac", res.serverErr)
	}
}
