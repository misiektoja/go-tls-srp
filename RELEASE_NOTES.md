# Release notes

All notable changes to this project are documented in this file.

## [0.2.0] - 21 Oct 2026

This release adds the **client side**. `srptls.Client` signs in to TLS-SRP servers with a username and password. Tested against OpenSSL 1.1.1w `s_server`.

### Client

* **`Client`** - Runs the TLS 1.2 SRP handshake as a client. `Config.Username` is required and `Config.ServerName` is sent as SNI. The client offers Extended Master Secret and secure renegotiation indication, refuses renegotiation and fails the handshake when the server's Finished message does not verify, so a server without the user's verifier cannot complete it. `Config.CipherSuites`, `Config.Rand` and `Config.KeyLogWriter` work as on the server.
* **`Config.MinGroupBits`** - Sets the smallest RFC 5054 group the client accepts. It is 2048 bits by default, so the 1024 and 1536 bit groups must be allowed explicitly. Groups outside RFC 5054 are always refused.
* **Client errors** - The handshake error wraps `ErrWrongPassword` when the server sends `bad_record_mac`, `ErrUnknownUsername` for `unknown_psk_identity` and `ErrAccessDenied` for `access_denied`. `ConnectionState.TLSUnique` on the client equals the server's value.

## [0.1.0] - 19 Oct 2026

This is the first release. Package `srptls` is a **TLS 1.2 server** that signs clients in with SRP from RFC 5054. It is a trimmed copy of `crypto/tls` from Go 1.27.2. Tested with curl 7.61.1, OpenSSL 1.1.1k `s_client`, libssl 3.5.9 and libssl 4.0.3.

### Server

* **SRP cipher suites** - `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` and `TLS_SRP_SHA_WITH_AES_128_CBC_SHA`. The 3DES suite is used only when listed in `Config.CipherSuites`.
* **All seven RFC 5054 groups** - From 1024 to 8192 bits.
* **`Config.GetVerifier`** - Returns the verifier for a username. `NewVerifier` creates one and OpenSSL `srpvfile` verifiers work as they are. `SimulatedVerifier` hides unknown usernames.
* **Refusals and wrong passwords** - `ErrAccessDenied` refuses a client before the SRP computation with an `access_denied` alert. A wrong password fails with an error that wraps `ErrWrongPassword`.
* **Extended Master Secret** - Supported together with secure renegotiation indication and SNI. `ConnectionState` reports the `tls-unique` channel binding and exports keying material.

### Known limitations

* **Not included** - The client side, TLS 1.3, session resumption, certificates and ALPN.
