# Running a server

A TLS-SRP server needs one thing from you: `Config.GetVerifier`, which returns the stored verifier
for the username in the ClientHello. The server needs no certificate and no private key.

## Accepting connections

`Listen` opens a listener whose `Accept` returns `*srptls.Conn` values. `NewListener` wraps a listener
you already have and `Server` wraps a single connection:

```go
--8<-- "example_test.go:server"
```

`Listen` returns an error when `GetVerifier` is not set. `NewListener` and `Server` do not check it.
A handshake without it fails with an `internal_error` alert.

The handshake runs when you call `Handshake` or `HandshakeContext` or on the first `Read` or `Write`.
After it completes, `ConnectionState().SRPUsername` holds the username the client
proved it holds the password of. [Connection state](../reference/connection-state.md) lists the
other fields.

## The GetVerifier callback

`GetVerifier` receives a `ClientHelloInfo`:

| Field | Content |
| --- | --- |
| `Username` | The username from the `srp` extension, as sent. It is 1 to 255 bytes and may not be valid UTF-8 |
| `ServerName` | The host name from the `server_name` extension. Empty when the client sent none |
| `CipherSuites` | The cipher suites the client offered |
| `Conn` | The underlying connection. Do not read from it or write to it |
| `Context()` | The handshake context, canceled when the handshake ends |

It is called once per handshake, after the server has chosen a cipher suite and before any SRP
computation. Its return value decides how the handshake continues:

| Return | Result |
| --- | --- |
| A verifier | The server validates it and continues. An invalid verifier ends the handshake with `internal_error` |
| `ErrUnknownUsername` | `unknown_psk_identity` alert. The client learns that the username does not exist |
| `ErrAccessDenied`, also wrapped | `access_denied` alert |
| Any other error | `internal_error` alert |

A ClientHello without the `srp` extension never reaches `GetVerifier`. The server answers it with
`unknown_psk_identity`, as [RFC 5054, Section 2.5.1.2](https://www.rfc-editor.org/rfc/rfc5054#section-2.5.1.2) recommends.

To hide which usernames exist, return a `SimulatedVerifier` for unknown ones. To refuse a client
before the SRP computation, return `ErrAccessDenied`.
[Unknown usernames and refusals](unknown-usernames.md) covers both.

The server's handshake error is the error `GetVerifier` returned, so `errors.Is` finds your own errors
too.

## Deadlines and handshake cost

The library sets no handshake deadline. A client that opens a connection and sends nothing holds it
open until you close it. Set a deadline on each accepted connection with `SetDeadline` before its handshake or run the
handshake with `HandshakeContext`. Canceling the context during the
handshake closes the connection.

The handshake is costly for the server. Once `GetVerifier` returns a verifier, the server computes
`B`, one modular exponentiation, before it reads anything more from the client. A ClientKeyExchange
with any value of `A` makes it compute two more before the client's Finished message shows whether
the client knows the password. The cost grows roughly with the square of the group size. Limit the
connections a client can open. A reverse proxy in front of the server can enforce both the limit and
the deadline. The [Security model](../security/security-model.md#denial-of-service) has the details.

## With net/http

`net/http` fills `Request.TLS` only for `crypto/tls` connections, so it stays nil here. Save the
connection with `http.Server.ConnContext` and read its `ConnectionState` in the handler. The handshake
runs on the first read, so `ReadHeaderTimeout` also limits it:

```go
--8<-- "example_test.go:http-server"
```

This code is `Example_httpServer` in `example_test.go`. The `config` it uses answers unknown usernames
with a simulated verifier, as shown on
[Unknown usernames and refusals](unknown-usernames.md#simulated-verifiers).

## Debugging

`Config.KeyLogWriter` writes the master secret of every handshake in the NSS key log format, which
Wireshark reads to decrypt a capture. Anyone with the log can decrypt the connections, so use it only
for debugging.
