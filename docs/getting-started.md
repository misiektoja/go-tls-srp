# Getting started

This page creates a verifier, starts a server and signs in to it with a client in one program. The
code is `Example` in `example_test.go`, which `go test` runs and checks against its output.

## Install

```bash
go get github.com/misiektoja/go-tls-srp
```

The module needs Go 1.27.3 or newer.

## Create a verifier

The server never sees the password. It stores a verifier made from the username, the password, a
random salt and one of the RFC 5054 groups:

```go
--8<-- "example_test.go:verifier"
```

A real server creates the verifier once when the user is enrolled. It stores the group size, the salt
and the value. [Verifiers and groups](guide/verifiers.md) describes what to store and how to
import verifiers made by OpenSSL.

## Start the server

`Config.GetVerifier` returns the stored verifier for the username in the ClientHello. `Listen`
returns a `net.Listener` whose connections are `*srptls.Conn`:

```go
--8<-- "example_test.go:server"
```

Returning `ErrUnknownUsername` tells the client that the username does not exist.
[Unknown usernames and refusals](guide/unknown-usernames.md) shows how to hide that instead.

## Connect a client

`Client` wraps a connection you dialed. The handshake checks the server's group and its Finished
message, so it succeeds only when the server holds the verifier of this username and password:

```go
--8<-- "example_test.go:client"
```

The program prints:

```text
hello device-1
TLS_SRP_SHA_WITH_AES_256_CBC_SHA
extended master secret: true
tls-unique bytes: 12
```

To run it from a checkout of the repository:

```bash
go test -run '^Example$' -v .
```

## What to change for production

* Store verifiers instead of passwords and protect them like password hashes. Whoever reads a verifier
  can test password guesses offline and can pose as the server to that user
  ([RFC 5054, Section 3.3](https://www.rfc-editor.org/rfc/rfc5054#section-3.3)).
* Decide how to answer unknown usernames. `SimulatedVerifier` makes them fail like a wrong password,
  as [Unknown usernames and refusals](guide/unknown-usernames.md) describes.
* Set a deadline on every accepted connection before its handshake and limit the connections a
  client can open. The library sets no handshake deadline. See
  [Running a server](guide/server.md#deadlines-and-handshake-cost).
* Limit password guessing by counting failed handshakes and refusing clients over the limit in
  `GetVerifier`. See [Limiting password guessing](guide/unknown-usernames.md#limiting-password-guessing).
* With `net/http`, use the setup on [Running a server](guide/server.md#with-nethttp) and
  [Connecting as a client](guide/client.md#with-nethttp), because `Request.TLS` and `Response.TLS`
  stay nil for these connections.
