# Channel binding and Extended Master Secret

## tls-unique

`ConnectionState.TLSUnique` holds the `tls-unique` channel binding of
[RFC 5929, Section 3](https://www.rfc-editor.org/rfc/rfc5929#section-3): the first Finished message of
the handshake. Every handshake here is a full handshake, so that is the client's Finished message,
12 bytes long. The client and the server report the same value.

An EST client that links its certificate request to the TLS connection base64 encodes this value and
puts it in the challenge-password attribute of its CSR. The EST server compares it with its own
`TLSUnique` ([RFC 7030, Section 3.5](https://www.rfc-editor.org/rfc/rfc7030#section-3.5)). Read the
value after the handshake:

```go
state := conn.ConnectionState()
challengePassword := base64.StdEncoding.EncodeToString(state.TLSUnique)
```

Before the handshake completes, `ConnectionState` returns zero values and `TLSUnique` is empty. The
value never changes afterwards, because the connection cannot renegotiate.

## Extended Master Secret

Extended Master Secret ([RFC 7627](https://www.rfc-editor.org/rfc/rfc7627)) derives the master secret
from a hash of the handshake messages up to and including the ClientKeyExchange instead of from the client and
server random values.

* The client always offers it.
* The server uses it whenever the client offers it.
* The client also completes a handshake with a server that does not use it.

`ConnectionState.ExtendedMasterSecret` reports whether the connection used it. When your protocol
depends on it, check the field after the handshake and close the connection when it is false.

## Exporting keying material

`ConnectionState.ExportKeyingMaterial(label, context, length)` derives key material from the
connection as [RFC 5705](https://www.rfc-editor.org/rfc/rfc5705) specifies. A nil context is left out
of the derivation, which is not the same as an empty one. It returns an error:

* before the handshake has completed,
* when the connection did not use Extended Master Secret,
* when the context is 65536 bytes or longer,
* for the labels the TLS key schedule reserves: `client finished`, `server finished`,
  `master secret`, `key expansion` and `extended master secret`.

Both sides of a connection export the same bytes for the same label, context and length.
