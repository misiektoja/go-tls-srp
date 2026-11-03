# Unknown usernames and refusals

`GetVerifier` decides what a client with an unknown username learns and whether a client is refused
before the SRP computation.

| `GetVerifier` returns | Alert | Client error wraps | The client learns |
| --- | --- | --- | --- |
| `SimulatedVerifier(...)` | `bad_record_mac` | `ErrWrongPassword` | Nothing. It looks like a wrong password |
| `ErrUnknownUsername` | `unknown_psk_identity` | `ErrUnknownUsername` | The username does not exist |
| `ErrAccessDenied`, also wrapped | `access_denied` | `ErrAccessDenied` | It was refused |

The first two rows follow [RFC 5054, Section 2.5.1.3](https://www.rfc-editor.org/rfc/rfc5054#section-2.5.1.3),
which lets a server either reveal an unknown username or simulate a verifier for it.

## Simulated verifiers

`SimulatedVerifier(seed, group, username)` returns a verifier for a username the server does not know.
The handshake then runs to the end and fails like a wrong password, so the client cannot tell whether
the username exists:

```go
--8<-- "example_test.go:simulated"
```

This is part of `Example_httpServer` in `example_test.go`, which reads the seed from the
`SRP_SIMULATED_SEED` environment variable.

The salt and the value are derived from the seed and the username with HMAC, so the same seed and
username always give the same salt. The salt is 20 bytes and never starts with a zero byte, like a
salt from `NewSalt`. The value is a pseudo-random number below `N` rather than `g^x`. Computing it
needs no modular exponentiation. Once `GetVerifier` returns, the handshake costs the server the same
work as with a real verifier. How long your own lookup takes before it returns is up to you.

The simulation holds only when the inputs stay fixed:

* **The seed is a secret key.** Generate at least 16 random bytes once and store them with the
  verifiers. Anyone who knows the seed can compute the salt of any unknown username and so tell
  unknown usernames from real ones.
* **Use the same seed everywhere.** A seed that differs between server instances or changes on a
  restart makes the salt of an unknown username change, which a real user's salt never does.
* **Use the group of the stored verifiers.** The server sends the group in the clear, so an unknown
  username answered in another group stands out. If your stored verifiers use more than one group,
  every unknown username still gets the one group you pass.

## Revealing unknown usernames

Returning `ErrUnknownUsername` sends an `unknown_psk_identity` alert and saves the server the SRP
computation. The client error wraps `ErrUnknownUsername`. Use it when usernames are not secret.

A ClientHello without the `srp` extension gets the same alert, without a call to `GetVerifier`.

## Refusing a client

Return `ErrAccessDenied` or an error that wraps it to refuse a client before the server does any SRP
computation. The server sends an `access_denied` alert and its handshake error is the error you
returned:

```go
GetVerifier: func(info *srptls.ClientHelloInfo) (*srptls.Verifier, error) {
	if limiter.blocked(info.Username) {
		return nil, fmt.Errorf("too many failed sign-ins for %q: %w", info.Username, srptls.ErrAccessDenied)
	}
	return lookup(info.Username)
},
```

## Limiting password guessing

Every handshake lets a client test one password guess, so an online attacker can keep trying.
[RFC 5054, Section 3.3](https://www.rfc-editor.org/rfc/rfc5054#section-3.3) asks servers to limit the
rate of attempts per address or per username. The library provides the two hooks. The counting is yours:

1. Count a failed sign-in when the server's handshake error wraps `ErrWrongPassword`. A wrong password
   and an unknown username answered with a simulated verifier both do.
2. Check the count in `GetVerifier` and return `ErrAccessDenied` once it is used up.

`ClientHelloInfo.Username` and `ClientHelloInfo.Conn.RemoteAddr()` identify the user and the address.
An attacker who alters the client's records on the way also causes `ErrWrongPassword`, so a counter
per username lets an attacker on the path lock that user out.
