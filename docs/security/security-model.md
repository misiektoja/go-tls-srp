# Security model

## What the handshake proves

A completed handshake proves to the server that the client knows the password the stored verifier was
made from. It proves to the client that the server holds that verifier. Neither side sends the
password or the verifier. No certificate is involved. Both proofs are the Finished messages: with
a wrong password or without the verifier, the two sides derive different keys and the handshake
fails ([RFC 5054, Section 2.6](https://www.rfc-editor.org/rfc/rfc5054#section-2.6)).

The username is not protected. The client sends it in the clear in the ClientHello
([RFC 5054, Section 3.3](https://www.rfc-editor.org/rfc/rfc5054#section-3.3)), so anyone on the path
can read it.

## What the library checks

* **Groups.** Both sides use only the seven groups of RFC 5054, Appendix A. The client refuses any
  other prime or generator and, by default, the 1024 and 1536 bit groups, with an
  `insufficient_security` alert.
* **Public values.** RFC 5054 requires both sides to refuse a public value that is zero modulo `N`
  and calls these checks crucial in Section 3.1. The server refuses such an `A` and the client such a
  `B` with an `illegal_parameter` alert. Both also refuse values that are not below `N` or that give
  `u = 0`.
* **Exponents.** The secret exponents `a` and `b` are 384 bits drawn from `Config.Rand`, above the
  256 bits RFC 5054 asks for.
* **Constant-time arithmetic.** The modular arithmetic uses
  [filippo.io/bigmod](https://pkg.go.dev/filippo.io/bigmod). The client computes
  `(B - k*g^x)^(a + u*x)` as `base^a * (base^u)^x`, so the secrets `a` and `x` stay in
  constant-time exponentiations and their sum is never formed.
* **Finished messages.** Both sides compare the Finished message in constant time.
* **Protocol.** Only TLS 1.2, no renegotiation, no session resumption and no compression.

## What RFC 5054 prescribes

SRP in TLS uses SHA-1 for the SRP values `x`, `u` and `k`. The cipher suites protect records with CBC
and HMAC-SHA1. RFC 5054, Section 3.4 explains why attacks on the collision resistance of SHA-1 do
not affect these uses. The CBC record layer keeps the Lucky13 countermeasures of `crypto/tls`, which
are partial: they apply only to the SHA-1 based MACs, which are the only MACs here.

## What the caller must do

* **Protect the verifiers.** Whoever reads a verifier can test password guesses offline and can pose
  as the server to that user (RFC 5054, Section 3.3).
* **Limit password guessing.** Every handshake tests one guess. Count failures and refuse clients over
  the limit, as [Limiting password guessing](../guide/unknown-usernames.md#limiting-password-guessing)
  describes.
* **Keep the simulated verifier seed secret and stable.** See
  [Simulated verifiers](../guide/unknown-usernames.md#simulated-verifiers).
* **Bound the handshake.** See [Denial of service](#denial-of-service).
* **Keep `KeyLogWriter` off in production.** The key log decrypts every connection it covers.
* **Choose passwords that resist offline guessing.** There is no tunable work factor: testing a guess
  against a stolen verifier costs two SHA-1 hashes and one modular exponentiation.

## Denial of service

The library sets no handshake deadline and no connection limit. A client that connects and sends
nothing keeps the connection open until the caller closes it.

The handshake is costly for the server. The client can make it do most of the work before proving
anything:

1. A single ClientHello makes the server call `GetVerifier` and, when it returns a verifier, compute
   `B` with one modular exponentiation.
2. A ClientKeyExchange with any value of `A` makes the server compute two more exponentiations for the
   premaster secret.
3. Only then does the client's Finished message show whether it knows the password.

The exponents have fixed lengths, so the cost grows roughly with the square of the group size. A
simulated verifier costs the same as a real one. Set a deadline on every accepted connection before its handshake with `SetDeadline` or
`HandshakeContext`. Limit the connections a client can open.
A reverse proxy in front of the server can enforce both. Returning `ErrAccessDenied` from
`GetVerifier` refuses a client before step 1's exponentiation.

## Fixes from Go

Most of the code is a copy of `crypto/tls`. A CI job that runs on every push and pull request to `dev` and `main` and
weekly compares the copied files with the newest Go release and fails when Go changed one of them, so fixes to Go's TLS
code are ported.
[Development](../development/development.md#following-go-releases) describes the process and the
[security policy](https://github.com/misiektoja/go-tls-srp/blob/main/SECURITY.md) how such fixes are
rated and released.

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub security advisories](https://github.com/misiektoja/go-tls-srp/security/advisories/new). The
[security policy](https://github.com/misiektoja/go-tls-srp/blob/main/SECURITY.md) describes the
process and the fix targets.
