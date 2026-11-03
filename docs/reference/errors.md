# Errors and alerts

## Sentinel errors

Test handshake errors with `errors.Is`.

| Error | On the server | On the client |
| --- | --- | --- |
| `ErrWrongPassword` | Wrapped by the handshake error when the client's Finished message does not decrypt or does not verify. A wrong password or a simulated verifier causes it. So does a client whose records were altered on the way | Wrapped by the handshake error when the server sends `bad_record_mac` |
| `ErrUnknownUsername` | Return it from `GetVerifier` to send `unknown_psk_identity`. The handshake error is the returned error | Wrapped by the handshake error when the server sends `unknown_psk_identity` |
| `ErrAccessDenied` | Return it or an error that wraps it from `GetVerifier` to send `access_denied`. The handshake error is the returned error | Wrapped by the handshake error when the server sends `access_denied` |

The common outcomes side by side:

| Cause | Server error | Alert to the client | Client error wraps |
| --- | --- | --- | --- |
| Wrong password or an unknown username with a `SimulatedVerifier` | Wraps `ErrWrongPassword` | `bad_record_mac` | `ErrWrongPassword` |
| `GetVerifier` returns `ErrUnknownUsername` | The error from `GetVerifier` | `unknown_psk_identity` | `ErrUnknownUsername` |
| `GetVerifier` returns `ErrAccessDenied` | The error from `GetVerifier` | `access_denied` | `ErrAccessDenied` |

## Alerts

An alert received from the peer is a `*net.OpError` in the error, with `Op` set to `"remote error"`.
The error text names the alert, for example `remote error: tls: bad record MAC`. An alert this side
sent appears as a `*net.OpError` with `Op` set to `"local error"` only when the record layer or the
message parser sent it, as with `bad_record_mac` and `decode_error`. The other checks return their own
error, which describes the cause.

Alerts the server sends:

| Alert | Cause |
| --- | --- |
| `protocol_version` | The ClientHello version is below TLS 1.2 |
| `illegal_parameter` | `A` is zero modulo `N`, not below `N` or gives `u = 0`. Also a ClientHello without null compression |
| `handshake_failure` | No common cipher suite, a non-empty `renegotiation_info` in the ClientHello or a client Finished message that decrypts but does not verify |
| `unknown_psk_identity` | No `srp` extension or `GetVerifier` returned `ErrUnknownUsername` |
| `access_denied` | `GetVerifier` returned `ErrAccessDenied` |
| `internal_error` | `GetVerifier` is not set, returned another error or returned an invalid verifier |
| `bad_record_mac` | A record does not decrypt. In the handshake this means a wrong password |
| `decode_error` | A malformed handshake message, including a repeated extension or an SNI name with a trailing dot |
| `unexpected_message` | A handshake message out of order, including any handshake message after the handshake |

The client sends the alerts listed on [Connecting as a client](../guide/client.md#what-the-client-checks).
It also sends `decode_error` for a malformed message, `unexpected_message` for a message out of order
and a `no_renegotiation` warning for a HelloRequest after the handshake.

## Other errors

* **Configuration errors.** A client `Config` without a usable username, `MinGroupBits` or cipher
  suite fails the handshake before anything is sent. `Listen` fails without `GetVerifier`.
* **`RecordHeaderError`.** The peer sent something that is not a TLS record, such as plain HTTP on
  the TLS port. Its `RecordHeader` holds the five bytes read. `Conn` holds the underlying connection
  when the bytes arrived in place of the first handshake message. It is nil after a handshake or after
  an alert was sent.
* **Context errors.** When the context passed to `HandshakeContext` is canceled during the handshake,
  the connection is closed and the context's error is returned.

Every handshake error is kept. Later calls to `Handshake`, `Read` and `Write` on the same `Conn` return
it again. After a canceled `HandshakeContext` the kept error is the one from the closed connection,
not the context error.
