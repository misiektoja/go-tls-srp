// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srptls

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
)

// pHash implements the P_hash function, as defined in RFC 4346, Section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// prf12 implements the TLS 1.2 pseudo-random function with SHA-256, which
// every SRP cipher suite uses, as defined in RFC 5246, Section 5.
func prf12(secret []byte, label string, seed []byte, keyLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	result := make([]byte, keyLen)
	pHash(result, secret, labelAndSeed, sha256.New)
	return result
}

const (
	masterSecretLength   = 48 // Length of a master secret in TLS 1.1.
	finishedVerifyLength = 12 // Length of verify_data in a Finished message.
)

const masterSecretLabel = "master secret"
const extendedMasterSecretLabel = "extended master secret"
const keyExpansionLabel = "key expansion"
const clientFinishedLabel = "client finished"
const serverFinishedLabel = "server finished"

// masterFromPreMasterSecret generates the master secret from the pre-master
// secret. See RFC 5246, Section 8.1.
func masterFromPreMasterSecret(preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	return prf12(preMasterSecret, masterSecretLabel, seed, masterSecretLength)
}

// extMasterFromPreMasterSecret generates the extended master secret from the
// pre-master secret and the transcript hash. See RFC 7627.
func extMasterFromPreMasterSecret(preMasterSecret, transcript []byte) []byte {
	return prf12(preMasterSecret, extendedMasterSecretLabel, transcript, masterSecretLength)
}

// keysFromMasterSecret generates the connection keys from the master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, Section 6.3.
func keysFromMasterSecret(masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterial := prf12(masterSecret, keyExpansionLabel, seed, n)
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}

// newFinishedHash returns the SHA-256 transcript hash of a TLS 1.2 handshake.
func newFinishedHash() finishedHash {
	return finishedHash{sha256.New()}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	h hash.Hash
}

// Write adds a handshake message to the transcript.
func (h *finishedHash) Write(msg []byte) (n int, err error) {
	return h.h.Write(msg)
}

// Sum returns the hash of the messages written so far.
func (h finishedHash) Sum() []byte {
	return h.h.Sum(nil)
}

// clientSum returns the contents of the verify_data member of a client's
// Finished message.
func (h finishedHash) clientSum(masterSecret []byte) []byte {
	return prf12(masterSecret, clientFinishedLabel, h.Sum(), finishedVerifyLength)
}

// serverSum returns the contents of the verify_data member of a server's
// Finished message.
func (h finishedHash) serverSum(masterSecret []byte) []byte {
	return prf12(masterSecret, serverFinishedLabel, h.Sum(), finishedVerifyLength)
}

// noEKMBecauseNoEMS is used as a value of ConnectionState.ekm when Extended
// Master Secret is not negotiated and thus we wish to fail all key-material
// export requests.
func noEKMBecauseNoEMS(label string, context []byte, length int) ([]byte, error) {
	return nil, errors.New("srptls: ExportKeyingMaterial is unavailable when Extended Master Secret is not negotiated")
}

// ekmFromMasterSecret generates exported keying material as defined in RFC 5705.
func ekmFromMasterSecret(masterSecret, clientRandom, serverRandom []byte) func(string, []byte, int) ([]byte, error) {
	return func(label string, context []byte, length int) ([]byte, error) {
		switch label {
		case "client finished", "server finished", "master secret", "key expansion", "extended master secret":
			// These values are reserved and may not be used.
			return nil, fmt.Errorf("srptls: reserved ExportKeyingMaterial label: %s", label)
		}

		seedLen := len(serverRandom) + len(clientRandom)
		if context != nil {
			seedLen += 2 + len(context)
		}
		seed := make([]byte, 0, seedLen)

		seed = append(seed, clientRandom...)
		seed = append(seed, serverRandom...)

		if context != nil {
			if len(context) >= 1<<16 {
				return nil, fmt.Errorf("srptls: ExportKeyingMaterial context too long")
			}
			seed = append(seed, byte(len(context)>>8), byte(len(context)))
			seed = append(seed, context...)
		}

		return prf12(masterSecret, label, seed, length), nil
	}
}
