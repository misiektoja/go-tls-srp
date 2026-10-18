# Changelog

Notable changes to go-tls-srp.

## [0.1.0] - 2026-10-19

First release. Package `srptls` is a TLS 1.2 server that signs clients in with SRP from RFC 5054.
It is a trimmed copy of `crypto/tls` from Go 1.27.2. Tested with curl 7.61.1, OpenSSL 1.1.1k
`s_client`, libssl 3.5.9 and libssl 4.0.3.

### Added
- **SRP cipher suites** `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` and `TLS_SRP_SHA_WITH_AES_128_CBC_SHA`.
  The 3DES suite is used only when listed in `Config.CipherSuites`.
- **All seven RFC 5054 groups**, from 1024 to 8192 bits.
- **`Config.GetVerifier`** returns the verifier for a username. `NewVerifier` creates one and
  OpenSSL `srpvfile` verifiers work as they are. `SimulatedVerifier` hides unknown usernames.
- **Refusals and wrong passwords.** `ErrAccessDenied` refuses a client before the SRP computation
  with an `access_denied` alert. A wrong password fails with an error that wraps
  `ErrWrongPassword`.
- **Extended Master Secret**, secure renegotiation indication and SNI. `ConnectionState` reports
  the `tls-unique` channel binding and exports keying material.

Not included: the client side, TLS 1.3, session resumption, certificates and ALPN.

[0.1.0]: https://github.com/misiektoja/go-tls-srp/releases/tag/v0.1.0
