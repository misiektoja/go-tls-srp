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
	// the client. On a client connection it is the name the client sent, which
	// is empty when Config.ServerName is empty or an IP address.
	ServerName string

	// SRPUsername is the username the client proved it holds the password of.
	// On a client connection it is Config.Username.
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
// instead to hide which usernames exist. A client handshake error wraps
// ErrUnknownUsername when the server sends that alert.
var ErrUnknownUsername = errors.New("srptls: unknown SRP username")

// ErrAccessDenied may be returned by Config.GetVerifier, also wrapped, to refuse a client, for
// example one over a rate limit. The server then aborts the handshake with an access_denied alert
// before it does the costly SRP computation. A client handshake error wraps ErrAccessDenied when
// the server sends that alert.
var ErrAccessDenied = errors.New("srptls: access denied")

// ErrWrongPassword is wrapped by the handshake error when the client's Finished message does not
// decrypt or does not verify. With SRP that means the client used another password than the
// verifier was made from, or the username is unknown and a simulated verifier answered. An
// attacker who alters the client's records on the way causes the same error. On the client it is
// wrapped when the server answers the client's Finished message with a bad_record_mac alert.
var ErrWrongPassword = errors.New("srptls: wrong SRP password")

// defaultMinGroupBits is the smallest SRP group a client accepts when Config.MinGroupBits is zero.
const defaultMinGroupBits = 2048

// A Config structure is used to configure a TLS-SRP client or server. Some
// fields apply to one side only, as their documentation says. After one has
// been passed to a TLS function it must not be modified. A Config may be
// reused.
type Config struct {
	// GetVerifier returns the SRP verifier for the username in the
	// ClientHello. It is required on the server and not used by the client.
	// Any error other than ErrUnknownUsername and ErrAccessDenied aborts the
	// handshake with an internal_error alert.
	GetVerifier func(*ClientHelloInfo) (*Verifier, error)

	// Username is the SRP username the client sends in the SRP extension of
	// its ClientHello, RFC 5054 Section 2.8.1. It is required on the client,
	// must be 1 to 255 bytes and is not used by the server. Like Password it
	// is hashed as given, without SASLprep.
	Username string

	// Password is the client's SRP password. It is not used by the server.
	Password string

	// ServerName is the host name the client sends in the Server Name
	// Indication extension. A trailing dot is removed. An IP address is not
	// sent. It is not used by the server.
	ServerName string

	// MinGroupBits is the prime size in bits of the smallest RFC 5054 group
	// the client accepts from the server. If zero, it is 2048, so the 1024
	// and 1536 bit groups must be allowed explicitly. It must not exceed 8192,
	// the largest group. It is not used by the server, which uses the group of
	// the verifier.
	MinGroupBits int

	// CipherSuites is the preference order of SRP cipher suites. The server
	// picks the first one the client offers. The client offers them in this
	// order. If nil, both use TLS_SRP_SHA_WITH_AES_256_CBC_SHA and then
	// TLS_SRP_SHA_WITH_AES_128_CBC_SHA. TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA is
	// used only when listed here.
	CipherSuites []uint16

	// Rand provides the source of entropy for nonces and the SRP private
	// values of the client and the server. If Rand is nil, crypto/rand is
	// used.
	Rand io.Reader

	// KeyLogWriter optionally specifies a destination for TLS master secrets
	// in NSS key log format that can be used to allow external programs
	// such as Wireshark to decrypt TLS connections. It works on both sides.
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

// cipherSuites returns the configured preference order of cipher suites.
func (c *Config) cipherSuites() []uint16 {
	if c.CipherSuites != nil {
		return c.CipherSuites
	}
	return defaultCipherSuites
}

// clientCipherSuites returns the cipher suites the client offers, in preference order. IDs of
// suites this package does not implement are left out.
func (c *Config) clientCipherSuites() []uint16 {
	var ids []uint16
	for _, id := range c.cipherSuites() {
		if cipherSuiteByID(id) != nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// minGroupBits returns the size of the smallest SRP group the client accepts.
func (c *Config) minGroupBits() int {
	if c.MinGroupBits == 0 {
		return defaultMinGroupBits
	}
	return c.MinGroupBits
}

// clientConfigError reports why config cannot be used for a client handshake, or nil.
func clientConfigError(config *Config) error {
	if config == nil {
		return errors.New("srptls: Client needs a non-nil Config")
	}
	// RFC 5054 Section 2.8.1: opaque srp_I<1..2^8-1>.
	if len(config.Username) < 1 || len(config.Username) > 255 {
		return errors.New("srptls: Config.Username must be 1 to 255 bytes")
	}
	largest := 0
	for _, g := range groups {
		largest = max(largest, g.bits)
	}
	if config.MinGroupBits < 0 || config.MinGroupBits > largest {
		return fmt.Errorf("srptls: Config.MinGroupBits %d is outside 0 to %d", config.MinGroupBits, largest)
	}
	if len(config.clientCipherSuites()) == 0 {
		return errors.New("srptls: Config.CipherSuites lists no SRP cipher suite of this package")
	}
	return nil
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
