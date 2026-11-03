# go-tls-srp

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-tls-srp?style=flat-square&color=blue)](https://github.com/misiektoja/go-tls-srp/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-tls-srp.svg)](https://pkg.go.dev/github.com/misiektoja/go-tls-srp)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-tls-srp/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-tls-srp/actions/workflows/test.yml)
[![Interoperability](https://github.com/misiektoja/go-tls-srp/actions/workflows/interop.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-tls-srp/actions/workflows/interop.yml)
[![Supply chain](https://github.com/misiektoja/go-tls-srp/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-tls-srp/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-tls-srp&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-tls-srp)

Package `srptls` is a TLS 1.2 client and server that sign in with SRP, the Secure Remote Password key
exchange of [RFC 5054](https://www.rfc-editor.org/rfc/rfc5054). The client proves that it knows a
password. The server stores only a verifier derived from the password, needs no certificate and
proves to the client that it holds the verifier.

Go's `crypto/tls` has no SRP. This module is a trimmed copy of `crypto/tls` from Go 1.27.2 that keeps
only the SRP handshake. It is written for systems that already use TLS-SRP, such as EST enrollment
with certificate-less mutual authentication.

## Contents

* [Install](#install)
* [Scope](#scope)
* [Getting started](#getting-started)
* [Documentation](#documentation)
* [Limitations](#limitations)
* [Support](#support)
* [Licence](#licence)

## Install

```bash
go get github.com/misiektoja/go-tls-srp
```

The module needs Go 1.27.3 or newer. The package is imported as `srptls`:

```go
import srptls "github.com/misiektoja/go-tls-srp"
```

## Scope

| Standard | Coverage | Enabled by |
| --- | --- | --- |
| RFC 5054 TLS-SRP | Client and server over TLS 1.2, the seven groups of Appendix A, `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` and `TLS_SRP_SHA_WITH_AES_128_CBC_SHA` | Always |
| RFC 5054 3DES suite | `TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA` | `Config.CipherSuites` |
| RFC 5054 small groups | The 1024 and 1536 bit groups on the client | `Config.MinGroupBits` |
| RFC 7627 Extended Master Secret | Always offered by the client, used by the server when offered | Always |
| RFC 5746 renegotiation indication | Signaling only, renegotiation is refused | Always |
| RFC 6066 server name indication | Sent by the client, reported on both sides | `Config.ServerName` |
| RFC 5929 `tls-unique` | `ConnectionState.TLSUnique` on both sides | Always |
| RFC 5705 keying material exporters | `ConnectionState.ExportKeyingMaterial` | Extended Master Secret |

The client is tested against OpenSSL 1.1.1w `s_server` in CI, see
[Tested implementations](https://misiektoja.github.io/go-tls-srp/interoperability/tested-implementations/).

## Getting started

The server returns the stored verifier for the username in the ClientHello. The client signs in with
the username and the password:

```go
l, err := srptls.Listen("tcp", ":8443", &srptls.Config{
	GetVerifier: func(info *srptls.ClientHelloInfo) (*srptls.Verifier, error) {
		return lookupVerifier(info.Username)
	},
})

conn := srptls.Client(raw, &srptls.Config{
	Username:   "device-1",
	Password:   password,
	ServerName: "est.example",
})
err = conn.HandshakeContext(ctx)
```

`NewVerifier` creates a verifier from a password and a salt from `NewSalt`. A failed handshake wraps
`ErrWrongPassword` when the password is wrong.
[Getting started](https://misiektoja.github.io/go-tls-srp/getting-started/) runs a complete server
and client. `Example` in [example_test.go](example_test.go) is the same program.

## Documentation

Full documentation is at
[misiektoja.github.io/go-tls-srp](https://misiektoja.github.io/go-tls-srp/).

* [Getting started](https://misiektoja.github.io/go-tls-srp/getting-started/)
* [Support matrix](https://misiektoja.github.io/go-tls-srp/support-matrix/)
* [Architecture](https://misiektoja.github.io/go-tls-srp/architecture/)
* [Running a server](https://misiektoja.github.io/go-tls-srp/guide/server/) and [Connecting as a client](https://misiektoja.github.io/go-tls-srp/guide/client/)
* [Verifiers and groups](https://misiektoja.github.io/go-tls-srp/guide/verifiers/), including OpenSSL verifier files
* [Unknown usernames and refusals](https://misiektoja.github.io/go-tls-srp/guide/unknown-usernames/)
* [Channel binding and Extended Master Secret](https://misiektoja.github.io/go-tls-srp/guide/channel-binding/)
* [Cipher suites](https://misiektoja.github.io/go-tls-srp/guide/cipher-suites/)
* [Errors and alerts](https://misiektoja.github.io/go-tls-srp/reference/errors/)
* [Security model](https://misiektoja.github.io/go-tls-srp/security/security-model/)

The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-tls-srp)
describes every exported identifier. Repository files:

* [CONTRIBUTING.md](CONTRIBUTING.md) lists the development checks and how the copy of `crypto/tls`
  follows Go releases.
* [SECURITY.md](SECURITY.md) explains how to report a vulnerability.
* [RELEASE_NOTES.md](RELEASE_NOTES.md) records user-visible changes per release.

## Limitations

* TLS 1.2 only, with the SRP cipher suites that need no certificate. No TLS 1.3.
* Only the seven groups of RFC 5054, Appendix A.
* No session resumption and no renegotiation. Every connection runs a full handshake.
* `*srptls.Conn` is not a `*tls.Conn`, so `net/http` leaves `Request.TLS` and `Response.TLS` nil and
  cannot negotiate HTTP/2.
* No handshake deadline, connection limit or limit on failed sign-ins. The server must set them, as
  the [Security model](https://misiektoja.github.io/go-tls-srp/security/security-model/#denial-of-service)
  describes.

[Known limitations](https://misiektoja.github.io/go-tls-srp/known-limitations/) explains each gap.

## Support

Ask questions and report bugs in [GitHub issues](https://github.com/misiektoja/go-tls-srp/issues).
Include the module version, the Go version, the peer and its version and the handshake error of both
sides. Report vulnerabilities privately as [SECURITY.md](SECURITY.md) describes.

## Licence

BSD-3-Clause, the licence of the Go project. See [LICENSE](LICENSE).
