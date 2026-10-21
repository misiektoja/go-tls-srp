// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// clientHandshakeState contains details of a client handshake in progress.
// It's discarded once the handshake has completed.
type clientHandshakeState struct {
	c            *Conn
	hello        *clientHelloMsg
	serverHello  *serverHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
}

// clientHandshake performs a full TLS 1.2 SRP handshake as a client. A
// fatal alert from the server is wrapped in the error it stands for.
func (c *Conn) clientHandshake() error {
	if err := clientConfigError(c.config); err != nil {
		return err
	}
	hello, err := c.makeClientHello()
	if err != nil {
		return err
	}
	hs := &clientHandshakeState{c: c, hello: hello}
	return serverAlertError(hs.handshake())
}

// makeClientHello builds the ClientHello. It offers only TLS 1.2, the SRP
// extension with the username, Extended Master Secret (RFC 7627) and the
// renegotiation_info extension (RFC 5746, Section 3.4) instead of the SCSV.
func (c *Conn) makeClientHello() (*clientHelloMsg, error) {
	config := c.config
	hello := &clientHelloMsg{
		vers:                         VersionTLS12,
		random:                       make([]byte, 32),
		cipherSuites:                 config.clientCipherSuites(),
		compressionMethods:           []uint8{compressionNone},
		serverName:                   hostnameInSNI(config.ServerName),
		secureRenegotiationSupported: true,
		secureRenegotiation:          []byte{},
		extendedMasterSecret:         true,
		srpUsername:                  []byte(config.Username),
	}
	if _, err := io.ReadFull(config.rand(), hello.random); err != nil {
		return nil, fmt.Errorf("srptls: short read from Rand: %w", err)
	}
	return hello, nil
}

// handshake runs the steps of RFC 5246, Section 7.3, with the SRP key
// exchange of RFC 5054 and no certificates.
func (hs *clientHandshakeState) handshake() error {
	c := hs.c

	hs.finishedHash = newFinishedHash()
	if _, err := c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil {
		return err
	}
	if err := hs.readServerHello(); err != nil {
		return err
	}
	group, salt, serverPublic, err := hs.readServerKeyExchange()
	if err != nil {
		return err
	}
	if err := hs.readServerHelloDone(); err != nil {
		return err
	}

	c.buffering = true
	if err := hs.sendClientKeyExchange(group, salt, serverPublic); err != nil {
		return err
	}
	hs.establishKeys()
	if err := hs.sendFinished(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}
	if err := hs.readFinished(); err != nil {
		return err
	}

	c.ekm = ekmFromMasterSecret(hs.masterSecret, hs.hello.random, hs.serverHello.random)
	c.serverName = hs.hello.serverName
	c.srpUsername = c.config.Username
	c.isHandshakeComplete.Store(true)

	return nil
}

// readServerHello reads the ServerHello and checks the version, the cipher
// suite and the extensions the server chose.
func (hs *clientHandshakeState) readServerHello() error {
	c := hs.c

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	hs.serverHello = serverHello

	// SRP cipher suites exist only up to TLS 1.2, and the client does not
	// offer older versions.
	if serverHello.vers != VersionTLS12 {
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("srptls: server selected TLS version %x, the client supports only TLS 1.2", serverHello.vers)
	}
	c.vers = VersionTLS12
	c.haveVers = true

	for _, id := range hs.hello.cipherSuites {
		if id == serverHello.cipherSuite {
			hs.suite = cipherSuiteByID(id)
			break
		}
	}
	if hs.suite == nil {
		c.sendAlert(alertIllegalParameter)
		return fmt.Errorf("srptls: server chose cipher suite %s, which the client did not offer", CipherSuiteName(serverHello.cipherSuite))
	}
	c.cipherSuite = hs.suite.id

	if serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return errors.New("srptls: server selected unsupported compression format")
	}

	// RFC 5746, Section 3.4.
	if len(serverHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("srptls: initial handshake had non-empty renegotiation extension")
	}

	// RFC 5246, Section 7.4.1.4: a server may only answer extensions the
	// client sent.
	if serverHello.unknownExtension || (serverHello.serverNameAck && hs.hello.serverName == "") {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("srptls: server sent an extension the client did not offer")
	}

	return nil
}

// readServerKeyExchange reads the ServerSRPParams of RFC 5054, Section
// 2.8.2, and checks the group.
func (hs *clientHandshakeState) readServerKeyExchange() (group *Group, salt, serverPublic []byte, err error) {
	c := hs.c

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return nil, nil, nil, err
	}
	skx, ok := msg.(*serverKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, nil, nil, unexpectedMessageError(skx, msg)
	}
	n, g, salt, serverPublic, ok := unmarshalSRPParams(skx.key)
	if !ok {
		c.sendAlert(alertDecodeError)
		return nil, nil, nil, errors.New("srptls: malformed SRP ServerKeyExchange")
	}

	// RFC 5054, Section 2.5.3: group parameters the client does not accept
	// must be rejected with insufficient_security. Only the groups of
	// Appendix A are accepted.
	group, err = GroupByParameters(n, g)
	if err != nil {
		c.sendAlert(alertInsufficientSecurity)
		return nil, nil, nil, errors.New("srptls: server sent SRP parameters that are not an RFC 5054 group")
	}
	if group.Bits() < c.config.minGroupBits() {
		c.sendAlert(alertInsufficientSecurity)
		return nil, nil, nil, fmt.Errorf("srptls: server chose the %d bit SRP group, below the minimum of %d bits", group.Bits(), c.config.minGroupBits())
	}

	return group, salt, serverPublic, nil
}

// readServerHelloDone reads the end of the server's first flight.
func (hs *clientHandshakeState) readServerHelloDone() error {
	c := hs.c

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	helloDone, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(helloDone, msg)
	}
	return nil
}

// sendClientKeyExchange sends A and derives the master secret from the
// SRP premaster secret.
func (hs *clientHandshakeState) sendClientKeyExchange(group *Group, salt, serverPublic []byte) error {
	c := hs.c

	// The salt is hashed as received. RFC 5054 defines it as an opaque
	// string and NewVerifier hashes it the same way.
	clientPublic, preMasterSecret, err := srpClientKeyExchange(group, salt, serverPublic,
		[]byte(c.config.Username), []byte(c.config.Password), c.config.rand())
	if errors.Is(err, errBadServerPublic) {
		// RFC 5054, Section 2.5.3 and Section 2.9.
		c.sendAlert(alertIllegalParameter)
		return err
	}
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	body, err := marshalSRPClientPublic(clientPublic)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	ckx := &clientKeyExchangeMsg{ciphertext: body}
	if _, err := c.writeHandshakeRecord(ckx, &hs.finishedHash); err != nil {
		return err
	}

	if hs.serverHello.extendedMasterSecret {
		c.extMasterSecret = true
		hs.masterSecret = extMasterFromPreMasterSecret(preMasterSecret, hs.finishedHash.Sum())
	} else {
		hs.masterSecret = masterFromPreMasterSecret(preMasterSecret, hs.hello.random, hs.serverHello.random)
	}
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	return nil
}

// establishKeys prepares the record protection of both directions.
func (hs *clientHandshakeState) establishKeys() {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	clientCipher := hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
	clientHash := hs.suite.mac(clientMAC)
	serverCipher := hs.suite.cipher(serverKey, serverIV, true /* for reading */)
	serverHash := hs.suite.mac(serverMAC)

	c.out.prepareCipherSpec(clientCipher, clientHash)
	c.in.prepareCipherSpec(serverCipher, serverHash)
}

// sendFinished sends the client's ChangeCipherSpec and Finished and keeps
// the Finished message as the tls-unique channel binding.
func (hs *clientHandshakeState) sendFinished() error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	if _, err := c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}
	copy(c.clientFinished[:], finished.verifyData)
	return nil
}

// errServerFinished means the server's Finished message decrypted but did not verify.
var errServerFinished = errors.New("srptls: server's Finished message is incorrect")

// readFinished reads the server's ChangeCipherSpec and Finished. Only a
// server that holds the verifier of the username derives the same keys, so
// a verified Finished message authenticates the server.
func (hs *clientHandshakeState) readFinished() error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	msg, err := c.readHandshake(nil)
	if sentAlert(err, alertBadRecordMAC) {
		return fmt.Errorf("srptls: server's Finished message does not decrypt, so the server does not hold the verifier of this username or the record was altered: %w", err)
	}
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errServerFinished
	}
	return nil
}

// receivedAlert returns the alert in err if the peer sent it.
func receivedAlert(err error) (alert, bool) {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" {
		a, ok := opErr.Err.(alert)
		return a, ok
	}
	return 0, false
}

// serverAlertError wraps a fatal alert the server sent during the handshake
// in the sentinel error it stands for, so that callers can use errors.Is.
func serverAlertError(err error) error {
	a, ok := receivedAlert(err)
	if !ok {
		return err
	}
	switch a {
	case alertBadRecordMAC:
		// RFC 5054, Section 2.6: the server could not decrypt the client's
		// Finished message, so the client used another password than the
		// verifier was made from, or the server simulated an unknown user.
		return fmt.Errorf("%w: %w", ErrWrongPassword, err)
	case alertUnknownPSKIdentity:
		// RFC 5054, Section 2.5.1.3.
		return fmt.Errorf("%w: %w", ErrUnknownUsername, err)
	case alertAccessDenied:
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return err
}

// hostnameInSNI converts name into an appropriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See RFC 6066, Section 3.
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
