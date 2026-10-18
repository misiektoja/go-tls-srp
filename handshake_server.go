// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

// serverHandshakeState contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
type serverHandshakeState struct {
	c            *Conn
	ctx          context.Context
	clientHello  *clientHelloMsg
	hello        *serverHelloMsg
	suite        *cipherSuite
	verifier     *Verifier
	finishedHash finishedHash
	masterSecret []byte
}

// serverHandshake performs a full TLS 1.2 SRP handshake as a server.
func (c *Conn) serverHandshake(ctx context.Context) error {
	clientHello, err := c.readClientHello()
	if err != nil {
		return err
	}

	hs := serverHandshakeState{
		c:           c,
		ctx:         ctx,
		clientHello: clientHello,
	}
	return hs.handshake()
}

// handshake runs the steps of RFC 5246, Section 7.3, with the SRP key exchange
// of RFC 5054 and no certificates.
func (hs *serverHandshakeState) handshake() error {
	c := hs.c

	if err := hs.processClientHello(); err != nil {
		return err
	}

	c.buffering = true
	if err := hs.pickCipherSuite(); err != nil {
		return err
	}
	if err := hs.getVerifier(); err != nil {
		return err
	}
	if err := hs.doFullHandshake(); err != nil {
		return err
	}
	if err := hs.establishKeys(); err != nil {
		return err
	}
	if err := hs.readFinished(c.clientFinished[:]); err != nil {
		return err
	}
	c.buffering = true
	if err := hs.sendFinished(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}

	c.ekm = ekmFromMasterSecret(hs.masterSecret, hs.clientHello.random, hs.hello.random)
	c.isHandshakeComplete.Store(true)

	return nil
}

// readClientHello reads a ClientHello message and selects TLS 1.2. A client
// that offers only an older version is refused.
func (c *Conn) readClientHello() (*clientHelloMsg, error) {
	if c.config == nil || c.config.GetVerifier == nil {
		c.sendAlert(alertInternalError)
		return nil, errors.New("srptls: Config.GetVerifier is not set")
	}

	// clientHelloMsg is included in the transcript, but we haven't initialized
	// it yet. doFullHandshake records it.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return nil, err
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(clientHello, msg)
	}

	// A client that supports TLS 1.3 also offers TLS 1.2 in the legacy
	// version field or in supported_versions, so the legacy field decides.
	if clientHello.vers < VersionTLS12 {
		c.sendAlert(alertProtocolVersion)
		return nil, fmt.Errorf("srptls: client offered only TLS versions below 1.2: %x", clientHello.vers)
	}
	c.vers = VersionTLS12
	c.haveVers = true

	return clientHello, nil
}

// processClientHello checks the ClientHello and prepares the ServerHello.
func (hs *serverHandshakeState) processClientHello() error {
	c := hs.c

	hs.hello = new(serverHelloMsg)
	hs.hello.vers = c.vers

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	if !foundCompression {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client does not support uncompressed connections")
	}

	// The server never negotiates TLS 1.3, so the downgrade canary of RFC 8446,
	// Section 4.1.3 does not apply.
	hs.hello.random = make([]byte, 32)
	if _, err := io.ReadFull(c.config.rand(), hs.hello.random); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	hs.hello.extendedMasterSecret = hs.clientHello.extendedMasterSecret
	hs.hello.secureRenegotiationSupported = hs.clientHello.secureRenegotiationSupported
	hs.hello.compressionMethod = compressionNone
	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}

	return nil
}

// pickCipherSuite selects the first SRP cipher suite of the server's
// preference order that the client offers.
func (hs *serverHandshakeState) pickCipherSuite() error {
	c := hs.c

	hs.suite = selectCipherSuite(c.config.cipherSuites(), hs.clientHello.cipherSuites)
	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return fmt.Errorf("srptls: no SRP cipher suite supported by both client and server; client offered: %x",
			hs.clientHello.cipherSuites)
	}
	c.cipherSuite = hs.suite.id

	return nil
}

// getVerifier looks up the verifier of the client's SRP username. RFC 5054,
// Section 2.5.1.2 requires unknown_psk_identity when the client chose an SRP
// cipher suite without sending the SRP extension.
func (hs *serverHandshakeState) getVerifier() error {
	c := hs.c

	if hs.clientHello.srpUsername == nil {
		c.sendAlert(alertUnknownPSKIdentity)
		return errors.New("srptls: client did not send an SRP username")
	}

	verifier, err := c.config.GetVerifier(&ClientHelloInfo{
		Username:     string(hs.clientHello.srpUsername),
		ServerName:   hs.clientHello.serverName,
		CipherSuites: hs.clientHello.cipherSuites,
		Conn:         c.conn,
		ctx:          hs.ctx,
	})
	if errors.Is(err, ErrUnknownUsername) {
		c.sendAlert(alertUnknownPSKIdentity)
		return err
	}
	if errors.Is(err, ErrAccessDenied) {
		c.sendAlert(alertAccessDenied)
		return err
	}
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if err := verifier.Validate(); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.verifier = verifier
	return nil
}

// doFullHandshake sends the server flight with the SRP parameters and
// derives the master secret from the client's public value.
func (hs *serverHandshakeState) doFullHandshake() error {
	c := hs.c

	if hs.clientHello.serverName != "" {
		hs.hello.serverNameAck = true
	}
	hs.hello.cipherSuite = hs.suite.id

	hs.finishedHash = newFinishedHash()
	if _, err := hs.finishedHash.Write(hs.clientHello.original); err != nil {
		return err
	}
	if _, err := hs.c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil {
		return err
	}

	srp, err := newSRPServer(hs.verifier, c.config.rand())
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	params, err := marshalSRPParams(hs.verifier.Group.n, hs.verifier.Group.g, hs.verifier.Salt, srp.public)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	skx := &serverKeyExchangeMsg{key: params}
	if _, err := hs.c.writeHandshakeRecord(skx, &hs.finishedHash); err != nil {
		return err
	}

	helloDone := new(serverHelloDoneMsg)
	if _, err := hs.c.writeHandshakeRecord(helloDone, &hs.finishedHash); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}

	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}
	clientPublic, ok := srpClientPublic(ckx.ciphertext)
	if !ok {
		c.sendAlert(alertDecodeError)
		return errors.New("srptls: malformed SRP ClientKeyExchange")
	}

	preMasterSecret, err := srp.premasterSecret(clientPublic)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return err
	}
	if hs.hello.extendedMasterSecret {
		c.extMasterSecret = true
		hs.masterSecret = extMasterFromPreMasterSecret(preMasterSecret, hs.finishedHash.Sum())
	} else {
		hs.masterSecret = masterFromPreMasterSecret(preMasterSecret, hs.clientHello.random, hs.hello.random)
	}
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.clientHello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	return nil
}

// establishKeys prepares the record protection of both directions.
func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	clientCipher := hs.suite.cipher(clientKey, clientIV, true /* for reading */)
	clientHash := hs.suite.mac(clientMAC)
	serverCipher := hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
	serverHash := hs.suite.mac(serverMAC)

	c.in.prepareCipherSpec(clientCipher, clientHash)
	c.out.prepareCipherSpec(serverCipher, serverHash)

	return nil
}

// readFinished reads the client's ChangeCipherSpec and Finished. A client
// with the wrong password derives other keys, so its Finished record fails
// with bad_record_mac before this check, as RFC 5054, Section 2.6 expects.
func (hs *serverHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	// finishedMsg is included in the transcript, but not until after we
	// check the client version, since the state before this message was
	// sent is used during verification.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client's Finished message is incorrect")
	}

	data, err := clientFinished.marshal()
	if err != nil {
		return err
	}
	hs.finishedHash.Write(data)

	copy(out, verify)
	c.srpUsername = string(hs.clientHello.srpUsername)
	return nil
}

// sendFinished sends the server's ChangeCipherSpec and Finished.
func (hs *serverHandshakeState) sendFinished() error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	if _, err := hs.c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}

	return nil
}
