// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// The marshalingFunction type is an adapter to allow the use of ordinary
// functions as cryptobyte.MarshalingValue.
type marshalingFunction func(b *cryptobyte.Builder) error

// Marshal calls f.
func (f marshalingFunction) Marshal(b *cryptobyte.Builder) error {
	return f(b)
}

// addBytesWithLength appends a sequence of bytes to the cryptobyte.Builder. If
// the length of the sequence is not the value specified, it produces an error.
func addBytesWithLength(b *cryptobyte.Builder, v []byte, n int) {
	b.AddValue(marshalingFunction(func(b *cryptobyte.Builder) error {
		if len(v) != n {
			return fmt.Errorf("invalid value length: expected %d, got %d", n, len(v))
		}
		b.AddBytes(v)
		return nil
	}))
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// readUint24LengthPrefixed acts like s.ReadUint24LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint24LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
}

// clientHelloMsg holds the ClientHello fields a TLS-SRP server uses. Other
// extensions are skipped.
type clientHelloMsg struct {
	original                     []byte
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuites                 []uint16
	compressionMethods           []uint8
	serverName                   string
	secureRenegotiationSupported bool
	secureRenegotiation          []byte
	extendedMasterSecret         bool
	// srpUsername is the srp_I value of the SRP extension, or nil if the
	// client did not send the extension. RFC 5054, Section 2.8.1.
	srpUsername []byte
}

// marshal returns the wire form. A parsed message returns the bytes it was
// parsed from, so that the transcript hash matches what the client sent.
func (m *clientHelloMsg) marshal() ([]byte, error) {
	if m.original != nil {
		return m.original, nil
	}

	var exts cryptobyte.Builder
	if len(m.serverName) > 0 {
		// RFC 6066, Section 3
		exts.AddUint16(extensionServerName)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8(0) // name_type = host_name
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes([]byte(m.serverName))
				})
			})
		})
	}
	if m.srpUsername != nil {
		// RFC 5054, Section 2.8.1
		exts.AddUint16(extensionSRP)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.srpUsername)
			})
		})
	}
	if m.extendedMasterSecret {
		// RFC 7627
		exts.AddUint16(extensionExtendedMasterSecret)
		exts.AddUint16(0) // empty extension_data
	}
	if m.secureRenegotiationSupported {
		// RFC 5746, Section 3.2
		exts.AddUint16(extensionRenegotiationInfo)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.secureRenegotiation)
			})
		})
	}
	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.sessionId)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range m.cipherSuites {
				b.AddUint16(suite)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.compressionMethods)
		})
		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

// unmarshal parses a ClientHello. It rejects duplicate extensions and
// malformed values of the extensions it reads.
func (m *clientHelloMsg) unmarshal(data []byte) bool {
	*m = clientHelloMsg{original: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) {
		return false
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false
	}
	m.cipherSuites = []uint16{}
	m.secureRenegotiationSupported = false
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return false
		}
		if suite == scsvRenegotiation {
			m.secureRenegotiationSupported = true
		}
		m.cipherSuites = append(m.cipherSuites, suite)
	}

	if !readUint8LengthPrefixed(&s, &m.compressionMethods) {
		return false
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true

		switch extension {
		case extensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return false
				}
				if nameType != 0 {
					continue
				}
				if len(m.serverName) != 0 {
					// Multiple names of the same name_type are prohibited.
					return false
				}
				m.serverName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.serverName, ".") {
					return false
				}
			}
		case extensionSRP:
			// RFC 5054, Section 2.8.1: opaque srp_I<1..2^8-1>
			if !readUint8LengthPrefixed(&extData, &m.srpUsername) ||
				len(m.srpUsername) == 0 {
				return false
			}
		case extensionRenegotiationInfo:
			// RFC 5746, Section 3.2
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return false
			}
			m.secureRenegotiationSupported = true
		case extensionExtendedMasterSecret:
			// RFC 7627
			m.extendedMasterSecret = true
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

// serverHelloMsg is the ServerHello of a full TLS 1.2 handshake.
type serverHelloMsg struct {
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	secureRenegotiationSupported bool
	secureRenegotiation          []byte
	extendedMasterSecret         bool
	serverNameAck                bool
}

// marshal returns the wire form of the ServerHello.
func (m *serverHelloMsg) marshal() ([]byte, error) {
	var exts cryptobyte.Builder
	if m.secureRenegotiationSupported {
		exts.AddUint16(extensionRenegotiationInfo)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.secureRenegotiation)
			})
		})
	}
	if m.extendedMasterSecret {
		exts.AddUint16(extensionExtendedMasterSecret)
		exts.AddUint16(0) // empty extension_data
	}
	if m.serverNameAck {
		exts.AddUint16(extensionServerName)
		exts.AddUint16(0)
	}

	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint8(typeServerHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.sessionId)
		})
		b.AddUint16(m.cipherSuite)
		b.AddUint8(m.compressionMethod)

		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

// unmarshal parses a ServerHello with the extensions this package sends.
func (m *serverHelloMsg) unmarshal(data []byte) bool {
	*m = serverHelloMsg{}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) ||
		!s.ReadUint16(&m.cipherSuite) ||
		!s.ReadUint8(&m.compressionMethod) {
		return false
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true

		switch extension {
		case extensionRenegotiationInfo:
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return false
			}
			m.secureRenegotiationSupported = true
		case extensionExtendedMasterSecret:
			m.extendedMasterSecret = true
		case extensionServerName:
			m.serverNameAck = true
		default:
			return false
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

// serverKeyExchangeMsg carries the encoded key exchange parameters.
type serverKeyExchangeMsg struct {
	key []byte
}

// marshal returns the wire form of the ServerKeyExchange.
func (m *serverKeyExchangeMsg) marshal() ([]byte, error) {
	length := len(m.key)
	x := make([]byte, length+4)
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.key)

	return x, nil
}

// unmarshal keeps the body of a ServerKeyExchange.
func (m *serverKeyExchangeMsg) unmarshal(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	m.key = data[4:]
	return true
}

// marshalSRPParams encodes ServerSRPParams from RFC 5054, Section 2.8.2. The
// numbers are sent without leading zero bytes, as OpenSSL does.
func marshalSRPParams(n, g, salt, b []byte) ([]byte, error) {
	var params cryptobyte.Builder
	params.AddUint16LengthPrefixed(func(params *cryptobyte.Builder) {
		params.AddBytes(trimLeadingZeros(n))
	})
	params.AddUint16LengthPrefixed(func(params *cryptobyte.Builder) {
		params.AddBytes(trimLeadingZeros(g))
	})
	params.AddUint8LengthPrefixed(func(params *cryptobyte.Builder) {
		params.AddBytes(salt)
	})
	params.AddUint16LengthPrefixed(func(params *cryptobyte.Builder) {
		params.AddBytes(trimLeadingZeros(b))
	})
	return params.Bytes()
}

// serverHelloDoneMsg ends the server's first flight.
type serverHelloDoneMsg struct{}

// marshal returns the wire form of the ServerHelloDone.
func (m *serverHelloDoneMsg) marshal() ([]byte, error) {
	x := make([]byte, 4)
	x[0] = typeServerHelloDone
	return x, nil
}

// unmarshal checks that the ServerHelloDone is empty.
func (m *serverHelloDoneMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

// clientKeyExchangeMsg carries the client's encoded key exchange value.
type clientKeyExchangeMsg struct {
	ciphertext []byte
}

// marshal returns the wire form of the ClientKeyExchange.
func (m *clientKeyExchangeMsg) marshal() ([]byte, error) {
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	return x, nil
}

// unmarshal keeps the body of a ClientKeyExchange.
func (m *clientKeyExchangeMsg) unmarshal(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-4 {
		return false
	}
	m.ciphertext = data[4:]
	return true
}

// srpClientPublic returns srp_A from a ClientKeyExchange body, the
// ClientSRPPublic structure of RFC 5054, Section 2.8.3.
func srpClientPublic(body []byte) ([]byte, bool) {
	s := cryptobyte.String(body)
	var a []byte
	if !readUint16LengthPrefixed(&s, &a) || len(a) == 0 || !s.Empty() {
		return nil, false
	}
	return a, true
}

// finishedMsg carries the verify_data of a Finished message.
type finishedMsg struct {
	verifyData []byte
}

// marshal returns the wire form of the Finished message.
func (m *finishedMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeFinished)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.verifyData)
	})

	return b.Bytes()
}

// unmarshal parses a Finished message.
func (m *finishedMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)
	return s.Skip(1) &&
		readUint24LengthPrefixed(&s, &m.verifyData) &&
		s.Empty()
}
