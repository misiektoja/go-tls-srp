# Connecting as a client

The client signs in with a username and a password. It needs no CA certificates: a server that
completes the handshake has proved that it holds the verifier of that username and password.

## Running the handshake

`Client` wraps a connection you dialed. `Config.Username` is required. In this code from `Example`,
`l` is the listener of the server on [Getting started](../getting-started.md):

```go
--8<-- "example_test.go:client"
```

The handshake runs when you call `Handshake` or `HandshakeContext` or on the first `Read` or `Write`.
Close the connection when the handshake fails.

| Field | Meaning |
| --- | --- |
| `Username` | Required, 1 to 255 bytes. Sent in the clear in the ClientHello |
| `Password` | The password the server's verifier was made from |
| `ServerName` | Sent as SNI. A trailing dot is removed and an IP address is not sent |
| `MinGroupBits` | The smallest group accepted. 2048 when zero |
| `CipherSuites` | The cipher suites to offer, in order. See [Cipher suites](cipher-suites.md) |
| `Rand` | The source of the client random, the SRP exponent and the CBC IVs. `crypto/rand` when nil |
| `KeyLogWriter` | NSS key log output for debugging |

The username and the password are hashed as given. RFC 5054 asks for SASLprep, but the library does
not apply it, as OpenSSL does not. Two passwords that look the same but differ in Unicode
normalization give different verifiers.

## Configuration errors

The handshake fails before anything is sent when:

* the `Config` is nil,
* the username is empty or longer than 255 bytes,
* `MinGroupBits` is negative or above 8192,
* `CipherSuites` lists none of the package's cipher suites.

## What the client checks

The client fails the handshake and sends an alert when the server:

| Server behavior | Alert the client sends |
| --- | --- |
| Selects a version other than TLS 1.2 | `protocol_version` |
| Selects a cipher suite the client did not offer or a compression method other than null | `illegal_parameter` |
| Sends a non-empty `renegotiation_info` | `handshake_failure` |
| Answers an extension the client did not send | `unsupported_extension` |
| Sends a group that is smaller than `MinGroupBits` or not in RFC 5054, Appendix A | `insufficient_security` |
| Sends `B` that is zero modulo `N`, not below `N` or gives `u = 0` | `illegal_parameter` |
| Sends a Finished message that does not decrypt | `bad_record_mac` |
| Sends a Finished message that decrypts but does not verify | `handshake_failure` |

The last two mean that the server does not hold the verifier of this username and password or that
the records were altered on the way. The client's error then wraps none of the sentinel errors
below, because those stand for alerts the server sent.

When the server refuses the client, the handshake error wraps a sentinel error:

| Server alert | Client error wraps | Meaning |
| --- | --- | --- |
| `bad_record_mac` | `ErrWrongPassword` | Wrong password or an unknown username the server hides with a simulated verifier |
| `unknown_psk_identity` | `ErrUnknownUsername` | The server says the username does not exist |
| `access_denied` | `ErrAccessDenied` | The server refused the client, for example over a rate limit |

[RFC 5054, Section 3.3](https://www.rfc-editor.org/rfc/rfc5054#section-3.3) warns that an attacker on
the path can insert an `unknown_psk_identity` alert, so do not draw conclusions from it alone.
[Errors and alerts](../reference/errors.md) lists every error form.

## Groups

The client accepts only the seven groups of RFC 5054 and, by default, only those of 2048 bits and
more. Set `MinGroupBits` to 1024 or 1536 to sign in to a server that still uses a smaller group:

```go
config := &srptls.Config{
	Username:     "device-1",
	Password:     password,
	MinGroupBits: 1024,
}
```

`MinGroupBits` is compared with the prime size, so a value between two group sizes accepts the
larger groups only.

## With net/http

Run the handshake in `http.Transport.DialTLSContext`. `net/http` fills `Response.TLS` only for
`crypto/tls` connections, so read the connection state from the `Conn` instead:

```go
--8<-- "example_test.go:http-client"
```

This code is `Example_httpClient` in `example_test.go`. The transport dials a new connection with a new
handshake whenever it has no idle connection to reuse.

## Renegotiation

The client never renegotiates. A HelloRequest from the server after the handshake is answered with a
`no_renegotiation` warning, the `Read` that received it returns an error and the connection can no
longer be written to.
