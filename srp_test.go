// Copyright 2026 The go-tls-srp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// unhex decodes a hexadecimal test vector that may contain spaces and newlines.
func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rfc5054Vectors holds the test vectors of RFC 5054, Appendix B.
var rfc5054Vectors = struct {
	username, password                       string
	salt, k, x, v, a, b, clientA, serverB, u string
	premaster                                string
}{
	username: "alice",
	password: "password123",
	salt:     "BEB25379 D1A8581E B5A72767 3A2441EE",
	k:        "7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F",
	x:        "94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124",
	v: `7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
		9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
		C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
		EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
		E955A5E2 9E7AB245 DB2BE315 E2099AFB`,
	a: `60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD
		DA2D4393`,
	b: `E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1
		05284D20`,
	clientA: `61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
		4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
		8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
		BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
		B349EF5D 76988A36 72FAC47B 0769447B`,
	serverB: `BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
		BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
		6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
		37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
		EB4012B7 D7665238 A8E3FB00 4B117B58`,
	u: "CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019",
	premaster: `B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
		233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C
		41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F
		3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D
		C346D7E4 74B29EDE 8A469FFE CA686E5A`,
}

// paddedExponent returns a reader that yields b left-padded to the server's
// private key length, so that newSRPServer uses the test vector's b.
func paddedExponent(b []byte) *bytes.Reader {
	out := make([]byte, srpPrivateKeyLen)
	copy(out[len(out)-len(b):], b)
	return bytes.NewReader(out)
}

// TestRFC5054Vectors checks the verifier, B and the premaster secret against
// RFC 5054, Appendix B.
func TestRFC5054Vectors(t *testing.T) {
	tv := rfc5054Vectors
	group, err := GroupByBits(1024)
	if err != nil {
		t.Fatal(err)
	}

	if got := group.k.Bytes(group.mod); !bytes.Equal(trimLeadingZeros(got), unhex(t, tv.k)) {
		t.Errorf("k = %X", got)
	}

	inner := sha1.Sum([]byte(tv.username + ":" + tv.password))
	x := sha1.Sum(append(unhex(t, tv.salt), inner[:]...))
	if !bytes.Equal(x[:], unhex(t, tv.x)) {
		t.Errorf("x = %X", x)
	}

	verifier, err := NewVerifier(group, []byte(tv.username), []byte(tv.password), unhex(t, tv.salt))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(trimLeadingZeros(verifier.Value), unhex(t, tv.v)) {
		t.Errorf("v = %X", verifier.Value)
	}

	srp, err := newSRPServer(verifier, paddedExponent(unhex(t, tv.b)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(trimLeadingZeros(srp.public), unhex(t, tv.serverB)) {
		t.Errorf("B = %X", srp.public)
	}

	u := sha1.Sum(append(group.pad(unhex(t, tv.clientA)), srp.public...))
	if !bytes.Equal(u[:], unhex(t, tv.u)) {
		t.Errorf("u = %X", u)
	}

	premaster, err := srp.premasterSecret(unhex(t, tv.clientA))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(premaster, unhex(t, tv.premaster)) {
		t.Errorf("premaster = %X", premaster)
	}

	// The client side of the same exchange, computed with math/big.
	client := srpClientPremaster(group, unhex(t, tv.a), srp.public, verifier.Salt, []byte(tv.username), []byte(tv.password))
	if !bytes.Equal(client.premaster, premaster) {
		t.Errorf("client premaster = %X", client.premaster)
	}
	if !bytes.Equal(client.public, unhex(t, tv.clientA)) {
		t.Errorf("A = %X", client.public)
	}
}

// TestSRPClientKeyExchange checks A and the client's premaster secret against
// RFC 5054, Appendix B, and the refusal of a B that is not in 1 to N-1.
func TestSRPClientKeyExchange(t *testing.T) {
	tv := rfc5054Vectors
	group, err := GroupByBits(1024)
	if err != nil {
		t.Fatal(err)
	}
	clientA, premaster, err := srpClientKeyExchange(group, unhex(t, tv.salt), unhex(t, tv.serverB),
		[]byte(tv.username), []byte(tv.password), paddedExponent(unhex(t, tv.a)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientA, unhex(t, tv.clientA)) {
		t.Errorf("A = %X", clientA)
	}
	if !bytes.Equal(premaster, unhex(t, tv.premaster)) {
		t.Errorf("premaster = %X", premaster)
	}
	if _, _, err := srpClientKeyExchange(group, unhex(t, tv.salt), unhex(t, tv.serverB),
		[]byte(tv.username), []byte(tv.password), bytes.NewReader(nil)); err == nil {
		t.Error("srpClientKeyExchange succeeded without entropy")
	}

	// RFC 5054, Section 2.5.3.
	n := new(big.Int).SetBytes(group.N())
	for name, b := range map[string][]byte{
		"empty":   nil,
		"zero":    {0, 0},
		"N":       group.N(),
		"2N":      new(big.Int).Lsh(n, 1).Bytes(),
		"above N": new(big.Int).Add(n, big.NewInt(1)).Bytes(),
	} {
		if _, _, err := srpClientKeyExchange(group, []byte{1}, b, []byte("user"), []byte("pass"), paddedExponent([]byte{9})); err != errBadServerPublic {
			t.Errorf("B %s: err = %v", name, err)
		}
	}
}

// TestGroups checks that every RFC 5054 group has a safe prime of the stated
// size. Groups above 2048 bits take seconds and are skipped with -short.
func TestGroups(t *testing.T) {
	want := map[int]byte{1024: 2, 1536: 2, 2048: 2, 3072: 5, 4096: 5, 6144: 5, 8192: 19}
	if len(groups) != len(want) {
		t.Fatalf("%d groups, want %d", len(groups), len(want))
	}
	for bits, g := range want {
		group, err := GroupByBits(bits)
		if err != nil {
			t.Fatal(err)
		}
		if group.Bits() != bits || len(group.N()) != bits/8 || !bytes.Equal(group.Generator(), []byte{g}) {
			t.Errorf("group %d: bits %d, %d bytes, g %X", bits, group.Bits(), len(group.N()), group.Generator())
		}
		if same, err := GroupByParameters(append([]byte{0}, group.N()...), []byte{0, g}); err != nil || same != group {
			t.Errorf("group %d: GroupByParameters = %v, %v", bits, same, err)
		}
		if testing.Short() && bits > 2048 {
			continue
		}
		n := new(big.Int).SetBytes(group.N())
		q := new(big.Int).Rsh(n, 1)
		if n.BitLen() != bits || !n.ProbablyPrime(4) || !q.ProbablyPrime(4) {
			t.Errorf("group %d: N is not a safe prime of %d bits", bits, bits)
		}
	}
	if _, err := GroupByBits(512); err == nil {
		t.Error("GroupByBits(512) succeeded")
	}
	if _, err := GroupByParameters([]byte{23}, []byte{5}); err == nil {
		t.Error("GroupByParameters accepted a group outside RFC 5054")
	}
}

// TestVerifierValidate checks the limits on stored verifiers.
func TestVerifierValidate(t *testing.T) {
	group, _ := GroupByBits(1024)
	good, err := NewVerifier(group, []byte("user"), []byte("pass"), []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]*Verifier{
		"nil":           nil,
		"no group":      {Salt: good.Salt, Value: good.Value},
		"zero group":    {Group: &Group{}, Salt: good.Salt, Value: good.Value},
		"empty salt":    {Group: group, Value: good.Value},
		"long salt":     {Group: group, Salt: make([]byte, 256), Value: good.Value},
		"zero value":    {Group: group, Salt: good.Salt, Value: []byte{0, 0}},
		"value N":       {Group: group, Salt: good.Salt, Value: group.N()},
		"value too big": {Group: group, Salt: good.Salt, Value: append([]byte{1}, group.N()...)},
	}
	for name, v := range tests {
		if err := v.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", name)
		}
	}
	padded := &Verifier{Group: group, Salt: good.Salt, Value: append([]byte{0, 0}, good.Value...)}
	if err := padded.Validate(); err != nil {
		t.Errorf("verifier with leading zeros: %v", err)
	}
	if _, err := NewVerifier(group, nil, []byte("pass"), []byte{1}); err == nil {
		t.Error("NewVerifier accepted an empty username")
	}
	if _, err := NewVerifier(nil, []byte("user"), []byte("pass"), []byte{1}); err == nil {
		t.Error("NewVerifier accepted a nil group")
	}
}

// TestSimulatedVerifier checks that simulated verifiers are stable per
// username and differ between usernames and seeds.
func TestSimulatedVerifier(t *testing.T) {
	group, _ := GroupByBits(3072)
	seed := []byte("0123456789abcdef0123456789abcdef")
	a1 := SimulatedVerifier(seed, group, []byte("ghost"))
	a2 := SimulatedVerifier(seed, group, []byte("ghost"))
	b := SimulatedVerifier(seed, group, []byte("phantom"))
	c := SimulatedVerifier([]byte("another seed"), group, []byte("ghost"))
	if err := a1.Validate(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a1.Salt, a2.Salt) || !bytes.Equal(a1.Value, a2.Value) {
		t.Error("simulated verifier is not stable")
	}
	if bytes.Equal(a1.Salt, b.Salt) || bytes.Equal(a1.Value, b.Value) {
		t.Error("simulated verifiers of two usernames match")
	}
	if bytes.Equal(a1.Salt, c.Salt) {
		t.Error("simulated verifiers of two seeds match")
	}
	if len(a1.Salt) != sha1.Size {
		t.Errorf("simulated salt is %d bytes, want %d like a real salt", len(a1.Salt), sha1.Size)
	}
}

// TestNewSalt checks the salt length and the leading byte rule.
func TestNewSalt(t *testing.T) {
	// The first draw starts with zero and must be discarded.
	r := bytes.NewReader(append(make([]byte, 20), bytes.Repeat([]byte{7}, 20)...))
	salt, err := NewSalt(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(salt, bytes.Repeat([]byte{7}, 20)) {
		t.Errorf("salt = %X", salt)
	}
	if _, err := NewSalt(bytes.NewReader(nil)); err == nil {
		t.Error("NewSalt succeeded without entropy")
	}
}

// TestPremasterRejectsBadA checks the client public value checks of RFC 5054,
// Section 2.5.4.
func TestPremasterRejectsBadA(t *testing.T) {
	group, _ := GroupByBits(1024)
	verifier, _ := NewVerifier(group, []byte("user"), []byte("pass"), []byte{1, 2, 3})
	srp, err := newSRPServer(verifier, paddedExponent([]byte{9}))
	if err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string][]byte{
		"empty":   nil,
		"zero":    {0},
		"N":       group.N(),
		"above N": append([]byte{1}, make([]byte, len(group.N()))...),
	} {
		if _, err := srp.premasterSecret(a); err != errBadClientPublic {
			t.Errorf("A %s: err = %v", name, err)
		}
	}
}

// srpClient holds the client side of one SRP exchange.
type srpClient struct {
	public    []byte
	premaster []byte
}

// srpClientPremaster computes A and the premaster secret of a client with
// math/big, independently of the server code: S = (B - k*g^x)^(a + u*x) mod N.
func srpClientPremaster(group *Group, a, serverB, salt, username, password []byte) srpClient {
	n := new(big.Int).SetBytes(group.N())
	g := new(big.Int).SetBytes(group.Generator())
	pad := func(b []byte) []byte {
		out := make([]byte, len(group.N()))
		return append(out[:len(out)-len(b)], b...)
	}

	kHash := sha1.Sum(append(group.N(), pad(group.Generator())...))
	k := new(big.Int).SetBytes(kHash[:])
	inner := sha1.Sum(append(append(append([]byte(nil), username...), ':'), password...))
	xHash := sha1.Sum(append(append([]byte(nil), salt...), inner[:]...))
	x := new(big.Int).SetBytes(xHash[:])

	aInt := new(big.Int).SetBytes(a)
	clientA := new(big.Int).Exp(g, aInt, n)
	b := new(big.Int).SetBytes(serverB)
	uHash := sha1.Sum(append(pad(clientA.Bytes()), pad(b.Bytes())...))
	u := new(big.Int).SetBytes(uHash[:])

	gx := new(big.Int).Exp(g, x, n)
	base := new(big.Int).Sub(b, new(big.Int).Mul(k, gx))
	base.Mod(base, n)
	exp := new(big.Int).Add(aInt, new(big.Int).Mul(u, x))
	s := new(big.Int).Exp(base, exp, n)
	return srpClient{public: clientA.Bytes(), premaster: s.Bytes()}
}
