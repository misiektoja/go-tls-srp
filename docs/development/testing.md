# Testing

`make test` runs `go vet` and the tests under the race detector. CI runs it on every push and pull
request to `dev` and `main`, after checking that the module files are tidy and the code is gofmt
formatted.

## What the tests cover

| File | Coverage |
| --- | --- |
| `srp_test.go` | The test vectors of RFC 5054, Appendix B, that every group prime is a safe prime, `Verifier.Validate`, `SimulatedVerifier`, `NewSalt` and the checks on `A` and `B` |
| `handshake_test.go` | The server against a minimal test client: handshakes in every group, cipher suite selection, the handshake without Extended Master Secret, refusals and their alerts, renegotiation and plain HTTP on the TLS port |
| `handshake_client_test.go` | The client against `Server` in every group and cipher suite. The client against a fake server that breaks the protocol on purpose: configuration errors, the ClientHello, SNI, key logs, refusals in both directions, renegotiation and `net/http` |
| `example_test.go` | The package examples. `Example` and `Example_openSSLVerifierFile` run and check their output |
| `interop_openssl_test.go` | The client against OpenSSL 1.1.1w `s_server`. See [Tested implementations](../interoperability/tested-implementations.md) |

`go test -short` skips the handshakes in the groups above 3072 bits and the safe prime check of the
groups above 2048 bits.

## Interoperability

`make test-interop` builds OpenSSL 1.1.1w and runs `TestOpenSSLServer`. Without
`SRPTLS_TEST_OPENSSL` that test is skipped, so `make test` needs no OpenSSL. The Interoperability
workflow runs it on every push and pull request to `dev` and `main` and caches the OpenSSL binary,
keyed on the hash of `scripts/build-openssl.sh`.

## Adding tests

A protocol change needs a negative test. A new refusal needs a case in the failure tables of
`handshake_test.go` or `handshake_client_test.go` that checks the alert and the error each side
reports.
