// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package srptls is a TLS 1.2 client and server that authenticate with SRP,
// the Secure Remote Password key exchange of RFC 5054. The client proves that
// it knows a password and the server proves that it holds the verifier made
// from it, without certificates. Use [Server] or [Listen] for the server side
// and [Client] for the client side. It is a trimmed copy of Go's crypto/tls
// with the SRP cipher suites only. It has no TLS 1.3, no session resumption,
// no renegotiation and no certificate authentication.
package srptls

// BUG(agl): The crypto/tls package only implements some countermeasures
// against Lucky13 attacks on CBC-mode encryption, and only on SHA1
// variants. See http://www.isg.rhul.ac.uk/tls/TLStiming.pdf and
// https://www.imperialviolet.org/2013/02/04/luckythirteen.html.

import (
	"errors"
	"net"
)

// Server returns a new TLS-SRP server side connection using conn as the
// underlying transport. The configuration must be non-nil and must set
// GetVerifier.
func Server(conn net.Conn, config *Config) *Conn {
	return &Conn{
		conn:   conn,
		config: config,
	}
}

// Client returns a new TLS-SRP client side connection using conn as the
// underlying transport. The configuration must be non-nil and must set
// Username. Otherwise the handshake fails before anything is sent. Like the
// server, the client runs the handshake on the first Read or Write, or on
// Handshake or HandshakeContext.
func Client(conn net.Conn, config *Config) *Conn {
	return &Conn{
		conn:     conn,
		config:   config,
		isClient: true,
	}
}

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	config *Config
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

// NewListener creates a Listener which accepts connections from an inner
// Listener and wraps each connection with [Server].
// The configuration must be non-nil and must set GetVerifier.
func NewListener(inner net.Listener, config *Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
// The configuration must be non-nil and must set GetVerifier.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || config.GetVerifier == nil {
		return nil, errors.New("srptls: Config.GetVerifier is not set")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}
