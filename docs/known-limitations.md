# Known limitations

## TLS 1.2 only

SRP has cipher suites only up to TLS 1.2, so the package neither offers nor negotiates TLS 1.3. It
refuses TLS 1.0 and 1.1. A peer that cannot do TLS 1.2 cannot connect.

## Only the RFC 5054 groups

The package has no way to define a group beyond the seven of RFC 5054, Appendix A. A verifier made in
another group cannot be used. The client refuses a server that sends one.

## Only the certificate-less SRP cipher suites

The `SRP_SHA_RSA` and `SRP_SHA_DSS` cipher suites, in which the server also signs with a certificate,
are not implemented. All three supported suites use CBC with HMAC-SHA1 and the partial Lucky13
countermeasures of `crypto/tls`.

## No session resumption

There are no session IDs and no session tickets. Every connection runs a full handshake with its
modular exponentiations, which matters for clients that open many short connections.

## No renegotiation

Neither side renegotiates. The server answers any handshake message after the handshake with an
`unexpected_message` alert. The client answers a HelloRequest with a `no_renegotiation` warning, after
which the connection can no longer be written to.

## No SASLprep

RFC 5054, Section 2.3 asks for usernames and passwords to be prepared with SASLprep. The package hashes
them as given, as OpenSSL does. Peers that apply SASLprep compute different verifiers for strings that
SASLprep changes.

## The username is sent in the clear

The client sends the username in the ClientHello without protection. RFC 5054 suggests renegotiating
an SRP handshake inside a first, protected one to hide it, which this package cannot do because it does
not renegotiate.

## Not crypto/tls

`*srptls.Conn` is not a `*tls.Conn`. Code that type-asserts `*tls.Conn`, such as `net/http` when it
fills `Request.TLS` and `Response.TLS`, does not see these connections as TLS. There is also no ALPN,
so HTTP/2 cannot be negotiated.

## No deadline or rate limit

The library sets no handshake deadline, no connection limit and no limit on failed sign-ins. The
caller provides them, as the [Security model](security/security-model.md#denial-of-service) describes.

## Other features

Certificates, ALPN, encrypt-then-MAC, compression, QUIC and Encrypted Client Hello are not
implemented.
