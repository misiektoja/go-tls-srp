# Changelog

Notable changes to go-tls-srp.

## [0.2.0] - 2026-10-21

Adds the client side. `srptls.Client` signs in to TLS-SRP servers with a username and password.
Tested against OpenSSL 1.1.1w `s_server`.

### Added
- **`Client`** runs the TLS 1.2 SRP handshake as a client. `Config.Username` is required and
  `Config.ServerName` is sent as SNI. The client offers Extended Master Secret and secure
  renegotiation indication, refuses renegotiation and fails the handshake when the server's
  Finished message does not verify, so a server without the user's verifier cannot complete it.
  `Config.CipherSuites`, `Config.Rand` and `Config.KeyLogWriter` work as on the server.
- **`Config.MinGroupBits`** sets the smallest RFC 5054 group the client accepts. It is 2048 bits
  by default, so the 1024 and 1536 bit groups must be allowed explicitly. Groups outside RFC 5054
  are always refused.
- **Client errors.** The handshake error wraps `ErrWrongPassword` when the server sends
  `bad_record_mac`, `ErrUnknownUsername` for `unknown_psk_identity` and `ErrAccessDenied` for
  `access_denied`. `ConnectionState.TLSUnique` on the client equals the server's value.

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

[0.2.0]: https://github.com/misiektoja/go-tls-srp/releases/tag/v0.2.0
[0.1.0]: https://github.com/misiektoja/go-tls-srp/releases/tag/v0.1.0
