# go-tls-srp

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-tls-srp?style=flat-square&color=blue)](https://github.com/misiektoja/go-tls-srp/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-tls-srp.svg)](https://pkg.go.dev/github.com/misiektoja/go-tls-srp)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-tls-srp/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-tls-srp/actions/workflows/test.yml)
[![Interoperability](https://github.com/misiektoja/go-tls-srp/actions/workflows/interop.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-tls-srp/actions/workflows/interop.yml)
[![Supply chain](https://github.com/misiektoja/go-tls-srp/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-tls-srp/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-tls-srp&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-tls-srp)

Package `srptls` is a TLS 1.2 client and server that sign in with SRP, the Secure Remote Password key exchange of [RFC 5054](https://www.rfc-editor.org/rfc/rfc5054). The client proves that it knows a password. The server stores only a verifier derived from the password, needs no certificate and proves to the client that it holds the verifier.

Go's `crypto/tls` has no SRP. This module is a trimmed copy of `crypto/tls` from Go 1.27.2 that keeps only the SRP handshake. It works with peers that already use TLS-SRP, such as EST clients built on libest or OpenSSL and EST servers that accept TLS-SRP.

## What it supports

* **TLS 1.2 only** on both sides. SRP has no TLS 1.3 cipher suites. Older versions are refused.
* **Cipher suites** `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` and `TLS_SRP_SHA_WITH_AES_128_CBC_SHA`, preferred in that order. `TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA` is used only when listed in `Config.CipherSuites`. The suites that also sign with a server certificate are not implemented.
* **Only the seven groups of RFC 5054, Appendix A**, from 1024 to 8192 bits. The client accepts 2048 bits and more unless `Config.MinGroupBits` allows the smaller groups.
* **Extended Master Secret** (RFC 7627). The client always offers it and the server uses it when offered. `ConnectionState.ExportKeyingMaterial` works only with it.
* **Secure renegotiation indication** (RFC 5746). Renegotiation itself is refused.
* **SNI and `tls-unique`.** The client sends `Config.ServerName` and both sides report it in `ConnectionState.ServerName`. `ConnectionState.TLSUnique` holds the channel binding.

Not included: TLS 1.3, session resumption and tickets, certificates, ALPN, encrypt-then-MAC, QUIC and ECH.

## Server usage

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

Create verifiers with `NewVerifier` and a salt from `NewSalt`. To use an OpenSSL verifier, such as an `srpvfile` entry, decode its salt and verifier to big-endian bytes without leading zeros and find the group with `GroupByBits` or `GroupByParameters`.

For an unknown username, return one of these:

* `SimulatedVerifier`. The handshake fails like a wrong password, so the client cannot tell whether the username exists. The seed is a secret key. Generate at least 16 random bytes once and store them with the verifiers, so every server instance uses the same seed across restarts. Pass the group of the stored verifiers. [Its documentation](https://pkg.go.dev/github.com/misiektoja/go-tls-srp#SimulatedVerifier) explains how another seed or group gives the username away.
* `ErrUnknownUsername`. The server sends an `unknown_psk_identity` alert, which tells the client that the username does not exist.

To refuse a client before the costly SRP computation, for example one over a rate limit, return `ErrAccessDenied` or an error that wraps it. The client gets an `access_denied` alert.

### With net/http

`Request.TLS` stays nil because `net/http` fills it only for `crypto/tls` connections. Save the connection with `http.Server.ConnContext` and read its `ConnectionState` in the handler. The handshake runs on the first read, so `ReadHeaderTimeout` also limits it. See `Example_httpServer` in [example_test.go](example_test.go).

## Client usage

`Client` wraps a connection. `Config.Username` is required:

```go
raw, err := net.DialTimeout("tcp", "est.example:8443", 10*time.Second)
if err != nil {
	return err
}
conn := srptls.Client(raw, &srptls.Config{
	Username:   "device-1",
	Password:   password,
	ServerName: "est.example",
})
if err := conn.HandshakeContext(ctx); err != nil {
	raw.Close()
	return err
}
tlsUnique := conn.ConnectionState().TLSUnique
```

The handshake runs in `Handshake`, `HandshakeContext` or the first `Read` or `Write`. It fails before anything is sent when `Username` is empty or longer than 255 bytes. The username and password are hashed as given, without SASLprep, as OpenSSL does.

The client fails the handshake when the server's Finished message does not verify, which means the server does not hold the user's verifier. It also refuses groups outside RFC 5054 or below `MinGroupBits` and a server value `B` that is zero modulo N.

An EST client puts `TLSUnique` in the challenge password of its CSR (RFC 7030, Section 3.5). With `net/http`, run the handshake in `http.Transport.DialTLSContext` and read the state from the connection, because `Response.TLS` stays nil. See `Example_httpClient` in [example_test.go](example_test.go).

## Errors

| Cause | Server error | Alert to the client | Client error wraps |
| --- | --- | --- | --- |
| Wrong password or a `SimulatedVerifier` | wraps `ErrWrongPassword` | `bad_record_mac` | `ErrWrongPassword` |
| `GetVerifier` returns `ErrUnknownUsername` | the error from `GetVerifier` | `unknown_psk_identity` | `ErrUnknownUsername` |
| `GetVerifier` returns `ErrAccessDenied` | the error from `GetVerifier` | `access_denied` | `ErrAccessDenied` |

An alert from the peer is a `*net.OpError` with `Op` set to `"remote error"`. After a failed handshake, `Conn.Handshake` returns the same error again.

## Security notes

* SRP in TLS uses SHA-1 for the SRP values, as RFC 5054 requires, and CBC with HMAC-SHA1 for the records. The CBC code keeps the partial Lucky13 countermeasures of `crypto/tls`.
* The big-number arithmetic of both sides uses [filippo.io/bigmod](https://pkg.go.dev/filippo.io/bigmod), the constant-time modular arithmetic of the Go standard library exported as a module.
* After `GetVerifier` returns, a simulated verifier costs the server the same work as a real one. The time of the lookup itself is up to the caller.
* Once `GetVerifier` returns a verifier, the server does one modular exponentiation before the client proves anything. A ClientHello of about 100 bytes is enough to cause it. The cost grows with the square of the group size. The library sets no handshake deadline. Limit the connections a client can open and set a deadline on each accepted connection before its handshake with `SetDeadline` or `HandshakeContext`. A reverse proxy can enforce both.
* To limit password guessing, count a failed sign-in when the handshake error wraps `ErrWrongPassword` and check the count in `GetVerifier`, returning `ErrAccessDenied` once it is used up.

## Tested clients

* OpenSSL 1.1.1k `s_client` and curl 7.61.1 on Rocky Linux 8.
* libssl 3.5.9 and 4.0.3 through the SRP API (`SSL_CTX_set_srp_username` and `SSL_CTX_set_srp_password`).

`openssl s_client` from OpenSSL 3.0 onward ignores `-srppass` and uses a wrong password ([openssl/openssl#32565](https://github.com/openssl/openssl/issues/32565)). Test with OpenSSL 1.1.1, curl or a program that calls libssl directly.

## Tested servers

* OpenSSL 1.1.1w `s_server` with `-srpvfile` and verifiers made by `openssl srp`.

`openssl s_server` from OpenSSL 3.0.22, 3.5.9, 3.6.5 and 4.0.3 closes the connection during its SRP user lookup, also with its own `s_client`.

`make test-interop` builds OpenSSL 1.1.1w from source under `bin/` and runs the client against its `s_server`. To use another OpenSSL 1.1.1 binary, set `SRPTLS_TEST_OPENSSL` to it and run `go test -run TestOpenSSLServer`.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) describes the development checks, how the copy of `crypto/tls` follows Go releases and the release process.

## Licence

BSD-3-Clause, the licence of the Go project. See [LICENSE](LICENSE).
