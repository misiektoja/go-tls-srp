# go-tls-srp

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-tls-srp?style=flat-square&color=blue)](https://github.com/misiektoja/go-tls-srp/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-tls-srp.svg)](https://pkg.go.dev/github.com/misiektoja/go-tls-srp)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-tls-srp/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-tls-srp/actions/workflows/test.yml)
[![Interoperability](https://github.com/misiektoja/go-tls-srp/actions/workflows/interop.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-tls-srp/actions/workflows/interop.yml)
[![Supply chain](https://github.com/misiektoja/go-tls-srp/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-tls-srp/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-tls-srp&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-tls-srp)

Package `srptls` is a TLS 1.2 client and server that sign in with SRP, the Secure Remote Password key exchange of [RFC 5054](https://www.rfc-editor.org/rfc/rfc5054). A client proves that it knows a password. The server stores only a verifier derived from that password and needs no certificate. It proves to the client that it holds that verifier.

Go's `crypto/tls` has no SRP. This module is a trimmed copy of `crypto/tls` from Go 1.27.2, cut down to the SRP handshake. The server is for devices that already authenticate with TLS-SRP, for example EST clients built on libest or OpenSSL. The client signs in to such servers, for example EST servers that accept TLS-SRP.

## What it supports

* **Client and server, TLS 1.2 only.** The server sends a `protocol_version` alert to a client that offers only TLS 1.0 or 1.1. The client refuses any version other than TLS 1.2. SRP has no TLS 1.3 cipher suites.
* **Cipher suites** `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` and `TLS_SRP_SHA_WITH_AES_128_CBC_SHA`, in that order by default. `TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA` is used only when listed in `Config.CipherSuites`. The suites that also sign with a server certificate are not implemented.
* **All seven groups of RFC 5054, Appendix A**, from 1024 to 8192 bits. The package offers and accepts no other groups. The client accepts groups of 2048 bits and more unless `Config.MinGroupBits` allows the 1024 or 1536 bit group.
* **Extended Master Secret** (RFC 7627). The client always offers it and the server uses it when the client offers it. `ConnectionState.ExportKeyingMaterial` works only on such connections.
* **Secure renegotiation indication** (RFC 5746). Renegotiation itself is refused on both sides.
* **SNI.** The client sends `Config.ServerName`. Both sides report it in `ConnectionState.ServerName`. The `tls-unique` channel binding is in `ConnectionState.TLSUnique` and is the same on both ends.

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

`NewVerifier` creates a verifier from a username, a password and a salt from `NewSalt`. A verifier exported by OpenSSL, such as an `srpvfile` entry, can be used directly. Decode its salt and verifier to big-endian bytes without leading zeros and pick the group with `GroupByBits` or `GroupByParameters`.

For an unknown username, return either a `SimulatedVerifier` or `ErrUnknownUsername`:

* With `SimulatedVerifier`, the handshake fails exactly like a wrong password, with a `bad_record_mac` alert. The client cannot tell whether the username exists. The seed is a secret key. Generate at least 16 random bytes once, store them with the verifiers and use the same seed on every server instance and across restarts. A seed that differs between instances or restarts lets a client spot an unknown username by its salt changing, and anyone who knows the seed can compute the salt of any unknown username. Pass the group of the stored verifiers, because the server sends it in the clear and a different group would give the username away as well.
* With `ErrUnknownUsername`, the server sends an `unknown_psk_identity` alert, which reveals that the username does not exist.

To refuse a client before the costly SRP computation, for example one over a rate limit, return `ErrAccessDenied` or an error that wraps it. The client gets an `access_denied` alert.

### With net/http

`net/http` only fills `Request.TLS` for `crypto/tls` connections, so it stays nil here. Store the connection with `http.Server.ConnContext` and read `ConnectionState` from it in the handler. The handshake runs on the first read of the connection, so `ReadHeaderTimeout` also limits how long it may take. See `Example_httpServer` in [example_test.go](example_test.go).

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

The client refuses a server whose Finished message does not verify, so a server that does not hold the verifier of the username fails the handshake. It also refuses groups outside RFC 5054, groups below `MinGroupBits` and a server value `B` that is zero modulo N.

An EST client puts `TLSUnique` in the challenge password of its CSR (RFC 7030, Section 3.5). With `net/http`, run the handshake in `http.Transport.DialTLSContext`. `Response.TLS` stays nil, so read the state from the connection. See `Example_httpClient` in [example_test.go](example_test.go).

## Errors

A wrong password, or an unknown user with a simulated verifier, fails the handshake with an error that wraps `ErrWrongPassword`. The client gets a `bad_record_mac` alert. `Conn.Handshake` returns the same error again after a failed handshake. An alert from the peer is a `*net.OpError` with `Op` set to `"remote error"`. A refused unknown username returns `ErrUnknownUsername` and a refusal from `GetVerifier` the error it returned. Other handshake errors describe the cause in their text.

On the client, the handshake error wraps `ErrWrongPassword` when the server answers with `bad_record_mac`, `ErrUnknownUsername` for `unknown_psk_identity` and `ErrAccessDenied` for `access_denied`. The client cannot tell a wrong password from an unknown username on a server that simulates verifiers.

## Security notes

* SRP in TLS uses SHA-1 for the SRP values, as RFC 5054 requires, and CBC with HMAC-SHA1 for the records. The CBC code keeps the partial Lucky13 countermeasures of `crypto/tls`.
* The big-number arithmetic of both sides uses [filippo.io/bigmod](https://pkg.go.dev/filippo.io/bigmod), the constant-time modular arithmetic of the Go standard library exported as a module.
* After `GetVerifier` returns, a simulated verifier costs the server the same work as a real one. The time of the lookup itself is up to the caller.
* The server computes its public value as soon as `GetVerifier` returns, before the client proves anything, so a ClientHello of about 100 bytes costs it one modular exponentiation. The cost grows with the square of the group size. The library sets no handshake deadline. Limit the connections a client can open and set a deadline on each accepted connection before its handshake, with `SetDeadline` or `HandshakeContext`, or let a reverse proxy enforce both.
* To limit password guessing, count a failed sign-in when the handshake error wraps `ErrWrongPassword` and check the count in `GetVerifier`, returning `ErrAccessDenied` once it is used up.

## Tested clients

* OpenSSL 1.1.1k `s_client` and curl 7.61.1 on Rocky Linux 8.
* libssl 3.5.9 and 4.0.3 through the SRP API (`SSL_CTX_set_srp_username` and `SSL_CTX_set_srp_password`).

`openssl s_client` from OpenSSL 3.0 onward ignores `-srppass` and uses a wrong password ([openssl/openssl#32565](https://github.com/openssl/openssl/issues/32565)). Test with OpenSSL 1.1.1, curl or a program that calls libssl directly.

## Tested servers

* OpenSSL 1.1.1w `s_server` with `-srpvfile` and verifiers made by `openssl srp`.

`openssl s_server` from OpenSSL 3.0.22, 3.5.9, 3.6.5 and 4.0.3 closes the connection during its SRP user lookup, also with its own `s_client`. `make test-interop` builds OpenSSL 1.1.1w from source under `bin/` and runs the client against its `s_server`. To use another OpenSSL 1.1.1 binary, set `SRPTLS_TEST_OPENSSL` to it and run `go test -run TestOpenSSLServer`.

## Development

The Makefile runs the same checks as CI:

```bash
make test           # go vet and the tests under the race detector
make lint           # golangci-lint
make actionlint     # lint the GitHub Actions workflows
make test-interop   # the client against OpenSSL 1.1.1w s_server
make govulncheck    # known vulnerabilities that reach the code
make gitleaks       # leaked credentials in the tree and the history
make help           # every target
```

The recipes use the Go version from `go.mod` and download it when needed. The pinned tools are installed under `bin/` on first use. Building OpenSSL needs a C compiler, make and perl. Most of the code is `crypto/tls` from Go, so `.golangci.yml` leaves out linters that only object to its style.

Pull requests to `main` and `dev` must pass the tests, lint, the OpenSSL interop test, govulncheck and gitleaks.

## Following Go releases

Commit `b52d68c` holds `crypto/tls` from Go 1.27.2 unchanged. The kept files are `alert.go`, `cipher_suites.go`, `common.go`, `conn.go`, `handshake_messages.go`, `handshake_server.go`, `prf.go` and `tls.go`. The client handshake in `handshake_client.go` follows the TLS 1.2 part of Go's `handshake_client.go`. The SRP code is in `srp.go` and `groups_rfc5054.go`.

`make upstream-check` compares those files of Go 1.27.2, the `UPSTREAM_GO_VERSION` in the Makefile, with the installed Go release and fails when one of them changed. The Upstream Go workflow runs it against the newest stable Go release on every push and weekly, so a fix in Go's TLS code shows up here within a week. To compare with a specific release instead, set `UPSTREAM_CANDIDATE=go1.28.0`.

`make go-version-check` fails when a newer patch release of the Go minor in `go.mod` exists, so the tests, lint and govulncheck run against a current standard library. The Upstream Go workflow runs it as well. When it fails, raise the `go` directive in `go.mod` to that release.

When the check fails, port the changes that affect the TLS 1.2 client or server, the CBC record layer or the handshake message parsing, then raise `UPSTREAM_GO_VERSION` to the release you ported. The check prints the diff. To see it for one file:

```bash
git diff --no-index "$(go1.27.2 env GOROOT)/src/crypto/tls/conn.go" "$(go env GOROOT)/src/crypto/tls/conn.go"
```

## Releases

[RELEASE_NOTES.md](RELEASE_NOTES.md) has one section per version. Before tagging, run the release check on `main`:

```bash
VERSION=v0.1.0 make release-check
```

It tests an export of `HEAD` and imports it from a separate module, so it catches files that are untracked or only present locally. A release starts when a version tag reachable from `main` is pushed:

```bash
git tag -s v0.1.0 -m 'v0.1.0'
git push origin main v0.1.0
```

The release workflow repeats the check on the tag, builds source archives, an SBOM and checksums, attests their provenance and creates a draft release with the release notes section as its description. Review the draft and publish it. Do not draft a release in the GitHub UI. That creates the tag and the workflow refuses to rebuild a published release.

## Licence

BSD-3-Clause, the licence of the Go project. See [LICENSE](LICENSE).
