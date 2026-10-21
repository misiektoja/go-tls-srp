// Copyright 2026 The go-tls-srp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"filippo.io/bigmod"
)

// Group is one of the seven SRP groups of RFC 5054 Appendix A. OpenSSL clients accept only
// these groups, so the package offers no way to define another one.
type Group struct {
	bits int
	n    []byte
	g    []byte
	mod  *bigmod.Modulus
	// gNat and k are reduced modulo N. k is SHA1(N | PAD(g)) from RFC 5054 Section 2.5.3.
	gNat *bigmod.Nat
	k    *bigmod.Nat
}

var groups = buildGroups()

// buildGroups parses the RFC 5054 constants once. A parse failure is a programming error.
func buildGroups() []*Group {
	out := make([]*Group, 0, len(rfc5054Groups))
	for _, def := range rfc5054Groups {
		n, err := hex.DecodeString(def.n)
		if err != nil || len(n)*8 != def.bits {
			panic("srptls: invalid RFC 5054 group constant")
		}
		mod, err := bigmod.NewModulus(n)
		if err != nil {
			panic("srptls: invalid RFC 5054 group constant")
		}
		gr := &Group{bits: def.bits, n: n, g: []byte{def.g}, mod: mod}
		gr.gNat, err = bigmod.NewNat().SetBytes(gr.g, mod)
		if err != nil {
			panic("srptls: invalid RFC 5054 group constant")
		}
		h := sha1.New()
		h.Write(n)
		h.Write(gr.pad(gr.g))
		gr.k, err = bigmod.NewNat().SetOverflowingBytes(h.Sum(nil), mod)
		if err != nil {
			panic("srptls: invalid RFC 5054 group constant")
		}
		out = append(out, gr)
	}
	return out
}

// GroupByBits returns the RFC 5054 group with a prime of the given size, such as 1536 or 3072.
func GroupByBits(bits int) (*Group, error) {
	for _, g := range groups {
		if g.bits == bits {
			return g, nil
		}
	}
	return nil, fmt.Errorf("srptls: no RFC 5054 group has %d bits", bits)
}

// GroupByParameters returns the RFC 5054 group whose prime and generator match. Leading zero
// bytes are ignored, so values from any encoding of the numbers match.
func GroupByParameters(n, g []byte) (*Group, error) {
	n, g = trimLeadingZeros(n), trimLeadingZeros(g)
	for _, gr := range groups {
		if hmac.Equal(gr.n, n) && hmac.Equal(gr.g, g) {
			return gr, nil
		}
	}
	return nil, errors.New("srptls: parameters are not an RFC 5054 group")
}

// Bits returns the size of the group's prime in bits.
func (g *Group) Bits() int { return g.bits }

// N returns a copy of the group's prime in big-endian bytes.
func (g *Group) N() []byte { return append([]byte(nil), g.n...) }

// Generator returns a copy of the group's generator in big-endian bytes.
func (g *Group) Generator() []byte { return append([]byte(nil), g.g...) }

// pad left-pads a big-endian value with zeros to the length of N, the PAD() of RFC 5054. The
// value must not be longer than N.
func (g *Group) pad(b []byte) []byte {
	out := make([]byte, len(g.n))
	copy(out[len(out)-len(b):], b)
	return out
}

// Verifier is the stored SRP record of one username: the group, the salt and the verifier
// v = g^x mod N. The server needs no password.
type Verifier struct {
	Group *Group
	// Salt is sent to the client exactly as stored. OpenSSL computes x from the salt as a number,
	// so a salt imported from an OpenSSL srpv file must not keep a leading zero byte.
	Salt []byte
	// Value is v in big-endian bytes, with or without leading zeros.
	Value []byte
}

// Validate checks the limits RFC 5054 and the group place on a verifier.
func (v *Verifier) Validate() error {
	if v == nil || v.Group == nil || v.Group.mod == nil {
		return errors.New("srptls: verifier has no RFC 5054 group")
	}
	if len(v.Salt) < 1 || len(v.Salt) > 255 {
		return errors.New("srptls: salt must be 1 to 255 bytes")
	}
	value := trimLeadingZeros(v.Value)
	if len(value) == 0 || len(value) > len(v.Group.n) {
		return errors.New("srptls: verifier is out of range")
	}
	if _, err := bigmod.NewNat().SetBytes(value, v.Group.mod); err != nil {
		return errors.New("srptls: verifier is not below N")
	}
	return nil
}

// NewVerifier computes the verifier of a username and password with RFC 5054 Section 2.4:
// x = SHA1(s | SHA1(I | ":" | P)) and v = g^x mod N. The bytes are hashed as given, without
// SASLprep, as OpenSSL does.
func NewVerifier(group *Group, username, password, salt []byte) (*Verifier, error) {
	if group == nil || group.mod == nil {
		return nil, errors.New("srptls: verifier has no RFC 5054 group")
	}
	if len(username) < 1 || len(username) > 255 {
		return nil, errors.New("srptls: username must be 1 to 255 bytes")
	}
	v := &Verifier{Group: group, Salt: append([]byte(nil), salt...), Value: group.exp(srpX(salt, username, password))}
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return v, nil
}

// srpX returns the private key x = SHA1(s | SHA1(I | ":" | P)) of RFC 5054 Section 2.6. The
// salt, username and password are hashed as given.
func srpX(salt, username, password []byte) []byte {
	inner := sha1.New()
	inner.Write(username)
	inner.Write([]byte(":"))
	inner.Write(password)
	outer := sha1.New()
	outer.Write(salt)
	outer.Write(inner.Sum(nil))
	return outer.Sum(nil)
}

// NewSalt returns a random salt of 20 bytes without a leading zero byte. OpenSSL clients
// treat the salt as a number and drop leading zeros, so such a salt would give them another x.
func NewSalt(rand io.Reader) ([]byte, error) {
	salt := make([]byte, 20)
	for {
		if _, err := io.ReadFull(rand, salt); err != nil {
			return nil, err
		}
		if salt[0] != 0 {
			return salt, nil
		}
	}
}

// SimulatedVerifier returns a verifier for a username the server does not know, as RFC 5054
// Section 2.5.1.3 suggests. The same seed and username always give the same salt, and the
// handshake fails like a wrong password. The verifier is a pseudo-random number below N rather
// than g^x, because the client never sees it and an exponentiation would make unknown usernames
// slower than known ones. Every server that answers the same clients must use the same seed.
func SimulatedVerifier(seed []byte, group *Group, username []byte) *Verifier {
	// A real salt never starts with a zero byte, so a simulated one must not either.
	var salt []byte
	for counter := byte(0); len(salt) == 0 || salt[0] == 0; counter++ {
		h := hmac.New(sha1.New, seed)
		h.Write([]byte("salt"))
		h.Write([]byte{counter})
		h.Write(username)
		salt = h.Sum(nil)
	}
	var value []byte
	for counter := byte(0); len(value) < len(group.n); counter++ {
		h := hmac.New(sha256.New, seed)
		h.Write([]byte("verifier"))
		h.Write([]byte{counter})
		h.Write(username)
		value = h.Sum(value)
	}
	// Every RFC 5054 prime fills its top bit, so the value fits and is reduced modulo N.
	v, err := bigmod.NewNat().SetOverflowingBytes(value[:len(group.n)], group.mod)
	if err != nil || v.IsZero() == 1 {
		v = bigmod.NewNat().ExpandFor(group.mod).Add(group.gNat, group.mod)
	}
	return &Verifier{Group: group, Salt: salt, Value: v.Bytes(group.mod)}
}

// exp returns g^e mod N in big-endian bytes.
func (g *Group) exp(e []byte) []byte {
	return bigmod.NewNat().Exp(g.gNat, e, g.mod).Bytes(g.mod)
}

// srpServer holds one handshake's ephemeral SRP state.
type srpServer struct {
	group *Group
	v     *bigmod.Nat
	b     []byte
	// public is B = k*v + g^b mod N in the length of N.
	public []byte
}

// srpPrivateKeyLen is the size of the random exponents a and b. RFC 5054 asks for at least
// 256 bits. OpenSSL uses 384 bits.
const srpPrivateKeyLen = 48

// newSRPServer draws b and computes B for a validated verifier.
func newSRPServer(verifier *Verifier, rand io.Reader) (*srpServer, error) {
	group := verifier.Group
	v, err := bigmod.NewNat().SetBytes(trimLeadingZeros(verifier.Value), group.mod)
	if err != nil {
		return nil, err
	}
	b := make([]byte, srpPrivateKeyLen)
	if _, err := io.ReadFull(rand, b); err != nil {
		return nil, err
	}
	public := bigmod.NewNat().Exp(group.gNat, b, group.mod)
	kv := bigmod.NewNat().ExpandFor(group.mod).Add(group.k, group.mod)
	kv.Mul(v, group.mod)
	public.Add(kv, group.mod)
	return &srpServer{group: group, v: v, b: b, public: public.Bytes(group.mod)}, nil
}

// errBadClientPublic means the client's A is zero modulo N or not below N.
var errBadClientPublic = errors.New("srptls: invalid client public value")

// premasterSecret returns S = (A * v^u)^b mod N with u = SHA1(PAD(A) | PAD(B)), as RFC 5054
// Section 2.6 defines. Leading zero bytes are removed, as RFC 5054 Section 2.1 requires for
// an implicit conversion and as OpenSSL does.
func (s *srpServer) premasterSecret(clientPublic []byte) ([]byte, error) {
	group := s.group
	clientPublic = trimLeadingZeros(clientPublic)
	if len(clientPublic) == 0 || len(clientPublic) > len(group.n) {
		return nil, errBadClientPublic
	}
	a, err := bigmod.NewNat().SetBytes(clientPublic, group.mod)
	if err != nil || a.IsZero() == 1 {
		return nil, errBadClientPublic
	}
	h := sha1.New()
	h.Write(group.pad(clientPublic))
	h.Write(s.public)
	u := h.Sum(nil)
	if allZero(u) {
		return nil, errBadClientPublic
	}
	base := bigmod.NewNat().Exp(s.v, u, group.mod)
	base.Mul(a, group.mod)
	premaster := bigmod.NewNat().Exp(base, s.b, group.mod).Bytes(group.mod)
	return trimLeadingZeros(premaster), nil
}

// errBadServerPublic means the server's B is zero modulo N, not below N or gives u = 0.
var errBadServerPublic = errors.New("srptls: invalid server public value")

// srpClientKeyExchange draws the client's exponent a and returns A = g^a mod N and the
// premaster secret S = (B - k*g^x)^(a + u*x) mod N of RFC 5054 Section 2.6, with
// u = SHA1(PAD(A) | PAD(B)) and x from srpX. Both are returned without leading zero bytes, as
// the server side expects. The group must be an RFC 5054 group.
func srpClientKeyExchange(group *Group, salt, serverPublic, username, password []byte, rand io.Reader) (clientPublic, premaster []byte, err error) {
	// RFC 5054 Section 2.5.3 refuses B % N = 0. An honest server sends B reduced modulo N, so
	// any value not below N is refused too.
	serverPublic = trimLeadingZeros(serverPublic)
	if len(serverPublic) == 0 || len(serverPublic) > len(group.n) {
		return nil, nil, errBadServerPublic
	}
	b, err := bigmod.NewNat().SetBytes(serverPublic, group.mod)
	if err != nil || b.IsZero() == 1 {
		return nil, nil, errBadServerPublic
	}

	a := make([]byte, srpPrivateKeyLen)
	if _, err := io.ReadFull(rand, a); err != nil {
		return nil, nil, err
	}
	public := group.exp(a)

	h := sha1.New()
	h.Write(public)
	h.Write(group.pad(serverPublic))
	u := h.Sum(nil)
	if allZero(u) {
		return nil, nil, errBadServerPublic
	}

	// base = B - k*g^x mod N, which is g^b for a server that holds v = g^x.
	x := srpX(salt, username, password)
	kgx := bigmod.NewNat().Exp(group.gNat, x, group.mod)
	kgx.Mul(group.k, group.mod)
	base := b.Sub(kgx, group.mod)

	// base^(a + u*x) is computed as base^a * (base^u)^x, so that the secret exponents a and x
	// stay in constant-time exponentiations and the sum a + u*x is never formed.
	s := bigmod.NewNat().Exp(base, a, group.mod)
	baseU := bigmod.NewNat().Exp(base, u, group.mod)
	s.Mul(bigmod.NewNat().Exp(baseU, x, group.mod), group.mod)
	return trimLeadingZeros(public), trimLeadingZeros(s.Bytes(group.mod)), nil
}

// trimLeadingZeros returns b without leading zero bytes.
func trimLeadingZeros(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// allZero reports whether every byte of b is zero.
func allZero(b []byte) bool {
	var acc byte
	for _, c := range b {
		acc |= c
	}
	return acc == 0
}
