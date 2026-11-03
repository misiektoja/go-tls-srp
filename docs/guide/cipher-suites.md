# Cipher suites

The package implements the three SRP cipher suites of
[RFC 5054, Section 2.7](https://www.rfc-editor.org/rfc/rfc5054#section-2.7) that need no server
certificate.

| Constant | ID | OpenSSL name | Encryption | Default |
| --- | --- | --- | --- | --- |
| `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` | `0xC020` | `SRP-AES-256-CBC-SHA` | AES-256-CBC | First |
| `TLS_SRP_SHA_WITH_AES_128_CBC_SHA` | `0xC01D` | `SRP-AES-128-CBC-SHA` | AES-128-CBC | Second |
| `TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA` | `0xC01A` | `SRP-3DES-EDE-CBC-SHA` | 3DES-EDE-CBC | No |

All three protect records with CBC and HMAC-SHA1 and use the TLS 1.2 PRF with SHA-256. RFC 5054
defines no AEAD SRP cipher suites. `CipherSuiteName` returns the standard name of an ID. For an ID the package does not
implement it returns a hexadecimal fallback such as `0xC02F`.

## Choosing a suite

`Config.CipherSuites` is the preference order on both sides. When it is nil, the order is AES-256 and
then AES-128, the order of libest and OpenSSL clients. The 3DES suite is used only when it is listed.

| Side | Rule |
| --- | --- |
| Server | Picks the first suite of its own order that the client offers, whatever the client's order. A ClientHello without a common suite gets a `handshake_failure` alert |
| Client | Offers its order and leaves out IDs the package does not implement. A `Config.CipherSuites` with none of the three suites fails the handshake before anything is sent |

The client refuses a ServerHello that selects a suite it did not offer with an `illegal_parameter`
alert. `ConnectionState.CipherSuite` reports the suite in use.

To offer or accept 3DES for an old peer, list it after the AES suites:

```go
config.CipherSuites = []uint16{
	srptls.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
	srptls.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
	srptls.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
}
```

## Not implemented

* `TLS_SRP_SHA_RSA_WITH_*` and `TLS_SRP_SHA_DSS_WITH_*`, which add a server certificate and a signed
  ServerKeyExchange.
* Encrypt-then-MAC. The CBC suites use MAC-then-encrypt. The record layer keeps the partial
  Lucky13 countermeasures of `crypto/tls`. See the [Security model](../security/security-model.md).
