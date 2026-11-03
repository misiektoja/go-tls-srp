# go-tls-srp

go-tls-srp is a Go library for TLS-SRP: TLS 1.2 with the Secure Remote Password key exchange of
[RFC 5054](https://www.rfc-editor.org/rfc/rfc5054). Its package `srptls` has a client and a server.
The client proves that it knows a password. The server stores only a verifier derived from the
password, needs no certificate and proves to the client that it holds the verifier.

Go's `crypto/tls` has no SRP. This module is a trimmed copy of `crypto/tls` from Go 1.27.2 that keeps
only the SRP handshake, so its API follows `crypto/tls`: a `Config`, a `Conn` that implements
`net.Conn`, `Client`, `Server`, `Listen` and `ConnectionState`. It is written for systems that already
use TLS-SRP, such as EST enrollment ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)) with
certificate-less mutual authentication.

```bash
go get github.com/misiektoja/go-tls-srp
```

The module needs Go 1.27.3 or newer. It depends on
[filippo.io/bigmod](https://pkg.go.dev/filippo.io/bigmod) for the SRP arithmetic and on
`golang.org/x/crypto/cryptobyte` for message parsing. The package name differs from the module path,
so import it with a name:

```go
import srptls "github.com/misiektoja/go-tls-srp"
```

## Where to go next

| I want to | Page |
| --- | --- |
| Run a server and a client on my machine | [Getting started](getting-started.md) |
| See which versions, cipher suites, groups and extensions are supported | [Support matrix](support-matrix.md) |
| Understand the handshake and how the code is organized | [Architecture](architecture.md) |
| Accept TLS-SRP clients | [Running a server](guide/server.md) |
| Sign in to a TLS-SRP server | [Connecting as a client](guide/client.md) |
| Create, store or import verifiers | [Verifiers and groups](guide/verifiers.md) |
| Hide which usernames exist or refuse a client | [Unknown usernames and refusals](guide/unknown-usernames.md) |
| Bind an EST request to the TLS connection | [Channel binding and Extended Master Secret](guide/channel-binding.md) |
| Look up a field, a default or an error | [Configuration](reference/configuration.md), [Connection state](reference/connection-state.md) and [Errors and alerts](reference/errors.md) |
| Find out which implementations were tested | [Tested implementations](interoperability/tested-implementations.md) |
| Know what the library protects and what it leaves to me | [Security model](security/security-model.md) |
| Check what is not supported | [Known limitations](known-limitations.md) |
| Look up a type or function | [Package documentation](https://pkg.go.dev/github.com/misiektoja/go-tls-srp) |
| See what changed in a release | [Release notes](https://github.com/misiektoja/go-tls-srp/blob/main/RELEASE_NOTES.md) |
| Report a vulnerability | [Security policy](https://github.com/misiektoja/go-tls-srp/blob/main/SECURITY.md) |
| Contribute | [Contributing](https://github.com/misiektoja/go-tls-srp/blob/main/CONTRIBUTING.md) |

## Related projects

Other PKI projects from the same maintainer:

* [certrally](https://misiektoja.github.io/certrally/): a command line client for certificate enrollment over CMP, EST and SCEP
* [cmp-issuer](https://misiektoja.github.io/cmp-issuer/): a cert-manager external issuer for CMP servers
* [go-acme-server](https://misiektoja.github.io/go-acme-server/): an embeddable ACME server library for Go (RFC 8555)
* [go-pki-cmp](https://misiektoja.github.io/go-pki-cmp/): a Go library for the Certificate Management Protocol (CMP) with a client and a server
* [go-pki-est](https://misiektoja.github.io/go-pki-est/): a Go library for Enrollment over Secure Transport (EST, RFC 7030) with a client and a server
* [go-pki-scep](https://misiektoja.github.io/go-pki-scep/): a Go library for SCEP (RFC 8894) with a client and a server handler
* [go-pkcs7](https://misiektoja.github.io/go-pkcs7/): a Go library for PKCS #7 and CMS (RFC 5652) signed and enveloped data
* [go-composite-mldsa](https://misiektoja.github.io/go-composite-mldsa/): a Go library for post-quantum composite ML-DSA signatures
