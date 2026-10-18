// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"hash"
)

// SRP cipher suite IDs from RFC 5054, Section 2.7. The suites that also sign
// with a server certificate are not implemented.
const (
	TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA uint16 = 0xc01a
	TLS_SRP_SHA_WITH_AES_128_CBC_SHA  uint16 = 0xc01d
	TLS_SRP_SHA_WITH_AES_256_CBC_SHA  uint16 = 0xc020
)

// defaultCipherSuites is the preference order when Config.CipherSuites is nil.
// It matches the order of libest and OpenSSL clients.
var defaultCipherSuites = []uint16{
	TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
	TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
}

// CipherSuiteName returns the standard name for the passed cipher suite ID,
// or a hexadecimal fallback if the suite is not one of this package's.
func CipherSuiteName(id uint16) string {
	switch id {
	case TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"
	case TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
		return "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"
	case TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
		return "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"
	}
	return "0x" + hexUint16(id)
}

// hexUint16 formats id as four upper-case hexadecimal digits.
func hexUint16(id uint16) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[id>>12], digits[id>>8&0xf], digits[id>>4&0xf], digits[id&0xf]})
}

// A cipherSuite is a TLS 1.2 SRP cipher suite. All of them use CBC with
// HMAC-SHA1 and the TLS 1.2 PRF with SHA-256.
type cipherSuite struct {
	id uint16
	// the lengths, in bytes, of the key material needed for each component.
	keyLen int
	macLen int
	ivLen  int
	cipher func(key, iv []byte, isRead bool) cbcMode
	mac    func(key []byte) hash.Hash
}

var cipherSuites = []*cipherSuite{
	{TLS_SRP_SHA_WITH_AES_256_CBC_SHA, 32, 20, 16, cipherAES, macSHA1},
	{TLS_SRP_SHA_WITH_AES_128_CBC_SHA, 16, 20, 16, cipherAES, macSHA1},
	{TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, cipher3DES, macSHA1},
}

// cipherSuiteByID returns the cipher suite with the given ID or nil.
func cipherSuiteByID(id uint16) *cipherSuite {
	for _, cipherSuite := range cipherSuites {
		if cipherSuite.id == id {
			return cipherSuite
		}
	}
	return nil
}

// selectCipherSuite returns the first cipher suite from ids, the server's
// preference order, which the client also offers.
func selectCipherSuite(ids, clientIDs []uint16) *cipherSuite {
	for _, id := range ids {
		candidate := cipherSuiteByID(id)
		if candidate == nil {
			continue
		}
		for _, clientID := range clientIDs {
			if id == clientID {
				return candidate
			}
		}
	}
	return nil
}

// cipher3DES returns a 3DES-CBC encrypter or decrypter.
func cipher3DES(key, iv []byte, isRead bool) cbcMode {
	block, _ := des.NewTripleDESCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv).(cbcMode)
	}
	return cipher.NewCBCEncrypter(block, iv).(cbcMode)
}

// cipherAES returns an AES-CBC encrypter or decrypter.
func cipherAES(key, iv []byte, isRead bool) cbcMode {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv).(cbcMode)
	}
	return cipher.NewCBCEncrypter(block, iv).(cbcMode)
}

// macSHA1 returns a SHA-1 based MAC. It is constant time when the SHA-1
// implementation offers ConstantTimeSum, as the standard one does.
func macSHA1(key []byte) hash.Hash {
	h := sha1.New
	if _, ok := h().(constantTimeHash); ok {
		h = newConstantTimeHash(h)
	}
	return hmac.New(h, key)
}

// constantTimeHash is a hash whose ConstantTimeSum runs in time independent of
// the data.
type constantTimeHash interface {
	hash.Hash
	ConstantTimeSum(b []byte) []byte
}

// cthWrapper wraps any hash.Hash that implements ConstantTimeSum, and replaces
// with that all calls to Sum. It's used to obtain a ConstantTimeSum-based HMAC.
type cthWrapper struct {
	h constantTimeHash
}

// Size returns the digest size.
func (c *cthWrapper) Size() int { return c.h.Size() }

// BlockSize returns the hash block size.
func (c *cthWrapper) BlockSize() int { return c.h.BlockSize() }

// Reset resets the wrapped hash.
func (c *cthWrapper) Reset() { c.h.Reset() }

// Write feeds data to the wrapped hash.
func (c *cthWrapper) Write(p []byte) (int, error) { return c.h.Write(p) }

// Sum appends the constant-time digest to b.
func (c *cthWrapper) Sum(b []byte) []byte { return c.h.ConstantTimeSum(b) }

// newConstantTimeHash wraps a hash constructor whose hashes implement
// ConstantTimeSum.
func newConstantTimeHash(h func() hash.Hash) func() hash.Hash {
	return func() hash.Hash {
		return &cthWrapper{h().(constantTimeHash)}
	}
}

// tls10MAC implements the TLS 1.0 MAC function. RFC 2246, Section 6.2.3.
func tls10MAC(h hash.Hash, out, seq, header, data, extra []byte) []byte {
	h.Reset()
	h.Write(seq)
	h.Write(header)
	h.Write(data)
	res := h.Sum(out)
	if extra != nil {
		h.Write(extra)
	}
	return res
}
