// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
)

const (
	maxPlaintext      = 16384        // maximum plaintext payload length
	maxCiphertext     = 16384 + 2048 // maximum ciphertext payload length
	recordHeaderLen   = 5            // record header length
	maxHandshake      = 65536        // maximum handshake we support (protocol max is 16 MB)
	maxUselessRecords = 16           // maximum number of consecutive non-advancing records
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeHelloRequest      uint8 = 0
	typeClientHello       uint8 = 1
	typeServerHello       uint8 = 2
	typeServerKeyExchange uint8 = 12
	typeServerHelloDone   uint8 = 14
	typeClientKeyExchange uint8 = 16
	typeFinished          uint8 = 20
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
const (
	extensionServerName           uint16 = 0
	extensionSRP                  uint16 = 12 // RFC 5054, Section 2.8.1
	extensionExtendedMasterSecret uint16 = 23
	extensionRenegotiationInfo    uint16 = 0xff01
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	// Version is the TLS version used by the connection. It is always VersionTLS12.
	Version uint16

	// HandshakeComplete is true if the handshake has concluded.
	HandshakeComplete bool

	// CipherSuite is the cipher suite negotiated for the connection, such as
	// TLS_SRP_SHA_WITH_AES_256_CBC_SHA.
	CipherSuite uint16

	// ServerName is the value of the Server Name Indication extension sent by
	// the client.
	ServerName string

	// SRPUsername is the username the client proved it holds the password of.
	SRPUsername string

	// ExtendedMasterSecret is true if the client and server used the extended
	// master secret of RFC 7627.
	ExtendedMasterSecret bool

	// TLSUnique contains the "tls-unique" channel binding value (see RFC 5929,
	// Section 3). It is the client's Finished message because every handshake
	// is a full handshake.
	TLSUnique []byte

	// ekm is a closure exposed via ExportKeyingMaterial.
	ekm func(label string, context []byte, length int) ([]byte, error)
}

// ExportKeyingMaterial returns length bytes of exported key material in a new
// slice as defined in RFC 5705. If context is nil, it is not used as part of
// the seed. It returns an error unless the connection used Extended Master
// Secret.
func (cs *ConnectionState) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	if cs.ekm == nil {
		return nil, errors.New("srptls: handshake has not completed")
	}
	return cs.ekm(label, context, length)
}

// ClientHelloInfo contains information from a ClientHello message to guide
// the GetVerifier callback.
type ClientHelloInfo struct {
	// Username is the SRP username from the ClientHello, as sent. It is
	// between 1 and 255 bytes and may not be valid UTF-8.
	Username string

	// ServerName indicates the name of the server requested by the client.
	// It is only set if the client is using SNI.
	ServerName string

	// CipherSuites lists the cipher suites offered by the client.
	CipherSuites []uint16

	// Conn is the underlying net.Conn for the connection. Do not read
	// from, or write to, this connection; that will cause the TLS
	// connection to fail.
	Conn net.Conn

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// Context returns the context of the handshake that is in progress.
// This context is a child of the context passed to HandshakeContext,
// if any, and is canceled when the handshake concludes.
func (c *ClientHelloInfo) Context() context.Context {
	return c.ctx
}

// ErrUnknownUsername may be returned by Config.GetVerifier. The server then
// aborts the handshake with an unknown_psk_identity alert, which tells the
// client that the username does not exist. Return a SimulatedVerifier
// instead to hide which usernames exist.
var ErrUnknownUsername = errors.New("srptls: unknown SRP username")

// ErrAccessDenied may be returned by Config.GetVerifier, also wrapped, to refuse a client, for
// example one over a rate limit. The server then aborts the handshake with an access_denied alert
// before it does the costly SRP computation.
var ErrAccessDenied = errors.New("srptls: access denied")

// A Config structure is used to configure a TLS-SRP server. After one has
// been passed to a TLS function it must not be modified. A Config may be
// reused.
type Config struct {
	// GetVerifier returns the SRP verifier for the username in the
	// ClientHello. It is required. Any error other than ErrUnknownUsername
	// and ErrAccessDenied aborts the handshake with an internal_error alert.
	GetVerifier func(*ClientHelloInfo) (*Verifier, error)

	// CipherSuites is the server's preference order of SRP cipher suites.
	// The server picks the first one the client offers. If nil, the server
	// uses TLS_SRP_SHA_WITH_AES_256_CBC_SHA and then
	// TLS_SRP_SHA_WITH_AES_128_CBC_SHA. TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA is
	// used only when listed here.
	CipherSuites []uint16

	// Rand provides the source of entropy for nonces and the server's SRP
	// private value. If Rand is nil, the server uses crypto/rand.
	Rand io.Reader

	// KeyLogWriter optionally specifies a destination for TLS master secrets
	// in NSS key log format that can be used to allow external programs
	// such as Wireshark to decrypt TLS connections.
	// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
	// Use of KeyLogWriter compromises security and should only be
	// used for debugging.
	KeyLogWriter io.Writer
}

// rand returns the configured entropy source or crypto/rand.
func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

// cipherSuites returns the server's preference order of cipher suites.
func (c *Config) cipherSuites() []uint16 {
	if c.CipherSuites != nil {
		return c.CipherSuites
	}
	return defaultCipherSuites
}

const keyLogLabelTLS12 = "CLIENT_RANDOM"

// writeKeyLog writes one NSS key log line if a KeyLogWriter is configured.
func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error {
	if c.KeyLogWriter == nil {
		return nil
	}

	logLine := fmt.Appendf(nil, "%s %x %x\n", label, clientRandom, secret)

	writerMutex.Lock()
	_, err := c.KeyLogWriter.Write(logLine)
	writerMutex.Unlock()

	if err != nil {
		return fmt.Errorf("srptls: KeyLogWriter: %w", err)
	}
	return nil
}

// writerMutex protects all KeyLogWriters globally. It is rarely enabled,
// and is only for debugging, so a global mutex saves space.
var writerMutex sync.Mutex

// handshakeMessage is a TLS handshake message with its wire encoding.
type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal([]byte) bool
}

// unexpectedMessageError describes a handshake message of the wrong type.
func unexpectedMessageError(wanted, got any) error {
	return fmt.Errorf("srptls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}
