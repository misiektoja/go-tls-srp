# Support matrix

What the client and the server implement. [Known limitations](known-limitations.md) explains the
gaps.

## Protocol versions

| Version | Client | Server |
| --- | --- | --- |
| TLS 1.2 | Offered, the only version | Negotiated |
| TLS 1.3 | Not offered | Not negotiated. A client that offers TLS 1.2 as well gets TLS 1.2 |
| TLS 1.0 and 1.1 | Not offered. A server that selects another version than TLS 1.2 gets a `protocol_version` alert | Refused with a `protocol_version` alert |

RFC 5054 defines SRP cipher suites only up to TLS 1.2, so there is nothing to negotiate in TLS 1.3.
The server decides on the version field of the ClientHello and ignores `supported_versions`.

## Cipher suites

| Cipher suite | ID | Default |
| --- | --- | --- |
| `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` | `0xC020` | Yes, first |
| `TLS_SRP_SHA_WITH_AES_128_CBC_SHA` | `0xC01D` | Yes, second |
| `TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA` | `0xC01A` | No, only when listed in `Config.CipherSuites` |

The `SRP_SHA_RSA` and `SRP_SHA_DSS` suites of RFC 5054, which also sign with a server certificate,
are not implemented. [Cipher suites](guide/cipher-suites.md) describes the selection rules.

## SRP groups

Both sides use only the seven groups of
[RFC 5054, Appendix A](https://www.rfc-editor.org/rfc/rfc5054#appendix-A).

| Prime size in bits | Generator | Client default |
| --- | --- | --- |
| 1024 | 2 | Refused unless `Config.MinGroupBits` allows it |
| 1536 | 2 | Refused unless `Config.MinGroupBits` allows it |
| 2048 | 2 | Accepted |
| 3072 | 5 | Accepted |
| 4096 | 5 | Accepted |
| 6144 | 5 | Accepted |
| 8192 | 19 | Accepted |

The server sends the group of the verifier that `GetVerifier` returns. The client refuses any other
prime or generator with an `insufficient_security` alert. See [Verifiers and groups](guide/verifiers.md).

## Extensions

| Extension | Client | Server |
| --- | --- | --- |
| `srp` ([RFC 5054, Section 2.8.1](https://www.rfc-editor.org/rfc/rfc5054#section-2.8.1)) | Sends `Config.Username` | Required. A ClientHello without it fails with `unknown_psk_identity` |
| `server_name` ([RFC 6066, Section 3](https://www.rfc-editor.org/rfc/rfc6066#section-3)) | Sends `Config.ServerName` without a trailing dot. Sends nothing for an empty name or an IP address | Reads the host name, passes it to `GetVerifier` and acknowledges it. Refuses a name with a trailing dot or two host names |
| `extended_master_secret` ([RFC 7627](https://www.rfc-editor.org/rfc/rfc7627)) | Always offered. A server without it is accepted | Used whenever the client offers it |
| `renegotiation_info` ([RFC 5746](https://www.rfc-editor.org/rfc/rfc5746)) | Sends the empty extension instead of the signaling cipher suite | Accepts the extension or the signaling cipher suite and answers with the empty extension |
| Any other | A server that answers with an extension the client did not send fails with `unsupported_extension` | Ignored |

A ClientHello that repeats an extension fails to parse and gets a `decode_error` alert.

## Features

| Feature | Status |
| --- | --- |
| Mutual authentication with a password and a verifier | Supported |
| `tls-unique` channel binding ([RFC 5929](https://www.rfc-editor.org/rfc/rfc5929)) | `ConnectionState.TLSUnique` on both sides |
| Keying material exporters ([RFC 5705](https://www.rfc-editor.org/rfc/rfc5705)) | `ConnectionState.ExportKeyingMaterial`, only with Extended Master Secret |
| NSS key log for debugging | `Config.KeyLogWriter` on both sides |
| Renegotiation | Refused. See [Known limitations](known-limitations.md#no-renegotiation) |
| Session resumption and tickets | Not implemented. Every handshake is a full handshake |
| Certificates | Not implemented |
| ALPN, encrypt-then-MAC, compression | Not implemented. Only null compression is accepted |
| TLS 1.3, QUIC, ECH | Not implemented |
