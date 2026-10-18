# go-tls-srp

Package `srptls` is a TLS 1.2 server that signs clients in with SRP, the Secure Remote Password key exchange of [RFC 5054](https://www.rfc-editor.org/rfc/rfc5054). A client proves that it knows a password. The server stores only a verifier derived from that password and needs no certificate.

Go's `crypto/tls` has no SRP. This module is a trimmed copy of `crypto/tls` from Go 1.27.2, cut down to the server side of the SRP handshake. It exists for devices that already authenticate with TLS-SRP, for example EST clients built on libest or OpenSSL.

## What it supports

* **Server only, TLS 1.2 only.** A client that offers only TLS 1.0 or 1.1 gets a `protocol_version` alert. SRP has no TLS 1.3 cipher suites.
* **Cipher suites** `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` and `TLS_SRP_SHA_WITH_AES_128_CBC_SHA`, in that order by default. `TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA` is used only when listed in `Config.CipherSuites`. The suites that also sign with a server certificate are not implemented.
* **All seven groups of RFC 5054, Appendix A**, from 1024 to 8192 bits. The package offers no other groups. OpenSSL clients refuse other groups by default.
* **Extended Master Secret** (RFC 7627) when the client offers it. `ConnectionState.ExportKeyingMaterial` works only on such connections.
* **Secure renegotiation indication** (RFC 5746). Renegotiation itself is refused.
* **SNI** is reported in `ConnectionState.ServerName`. The `tls-unique` channel binding is in `ConnectionState.TLSUnique`.

Not included: the client side, TLS 1.3, session resumption and tickets, certificates, ALPN, encrypt-then-MAC, QUIC and ECH.

## Usage

`Config.GetVerifier` returns the stored verifier for the username in the ClientHello:

```go
config := &srptls.Config{
	GetVerifier: func(info *srptls.ClientHelloInfo) (*srptls.Verifier, error) {
		if v, ok := store[info.Username]; ok {
			return v, nil
		}
		return srptls.SimulatedVerifier(seed, group, []byte(info.Username)), nil
	},
}
l, err := srptls.Listen("tcp", ":8443", config)
```

`NewVerifier` creates a verifier from a username, a password and a salt from `NewSalt`. A verifier exported by OpenSSL, such as an `srpvfile` entry, can be used directly. Decode its salt and verifier to big-endian bytes without leading zeros and pick the group with `GroupByBits` or `GroupByParameters`.

For an unknown username, return either a `SimulatedVerifier` or `ErrUnknownUsername`:

* With `SimulatedVerifier`, the handshake fails exactly like a wrong password, with a `bad_record_mac` alert. The client cannot tell whether the username exists. Use the same seed on every server instance and keep it across restarts. Otherwise a client can spot an unknown username by its salt changing.
* With `ErrUnknownUsername`, the server sends an `unknown_psk_identity` alert, which reveals that the username does not exist.

### With net/http

`net/http` only fills `Request.TLS` for `crypto/tls` connections, so it stays nil here. Store the connection with `http.Server.ConnContext` and read `ConnectionState` from it in the handler. The handshake runs on the first read of the connection, so `ReadHeaderTimeout` also limits how long it may take. See `Example_httpServer` in [example_test.go](example_test.go).

## Errors

A wrong password, or an unknown user with a simulated verifier, fails the handshake with a `*net.OpError` whose text is `local error: tls: bad record MAC`. An alert from the client is a `*net.OpError` with `Op` set to `"remote error"`. A refused unknown username returns `ErrUnknownUsername`. Other handshake errors describe the cause in their text.

## Security notes

* SRP in TLS uses SHA-1 for the SRP values, as RFC 5054 requires, and CBC with HMAC-SHA1 for the records. The CBC code keeps the partial Lucky13 countermeasures of `crypto/tls`.
* The server's big-number arithmetic uses [filippo.io/bigmod](https://pkg.go.dev/filippo.io/bigmod), the constant-time modular arithmetic of the Go standard library exported as a module.
* After `GetVerifier` returns, a simulated verifier costs the server the same work as a real one. The time of the lookup itself is up to the caller. Counting attempts per username in `GetVerifier` lets a caller rate-limit password guessing.

## Tested clients

* OpenSSL 1.1.1k `s_client` and curl 7.61.1 on Rocky Linux 8.
* libssl 3.5.9 and 4.0.3 through the SRP API (`SSL_CTX_set_srp_username` and `SSL_CTX_set_srp_password`).

`openssl s_client` from OpenSSL 3.0 onward ignores `-srppass` and uses a wrong password ([openssl/openssl#32565](https://github.com/openssl/openssl/issues/32565)). Test with OpenSSL 1.1.1, curl or a program that calls libssl directly.

## Following Go releases

Commit `b52d68c` holds `crypto/tls` from Go 1.27.2 unchanged. The kept files are `alert.go`, `cipher_suites.go`, `common.go`, `conn.go`, `handshake_messages.go`, `handshake_server.go`, `prf.go` and `tls.go`. The SRP code is in `srp.go` and `groups_rfc5054.go`.

To pick up fixes from a newer Go release, compare its `crypto/tls` with Go 1.27.2 for those files and port the changes that affect the TLS 1.2 server, the CBC record layer or the handshake message parsing:

```bash
git diff --no-index "$(go1.27.2 env GOROOT)/src/crypto/tls/conn.go" "$(go env GOROOT)/src/crypto/tls/conn.go"
```

## Licence

BSD-3-Clause, the licence of the Go project. See [LICENSE](LICENSE).
