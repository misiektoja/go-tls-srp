# Tested implementations

## OpenSSL s_server

The Interoperability workflow runs the client against `openssl s_server` from OpenSSL 1.1.1w on every
push and pull request to `dev` and `main`. The test is `TestOpenSSLServer` in
`interop_openssl_test.go`.

| Item | Value |
| --- | --- |
| Peer | `openssl s_server` from OpenSSL 1.1.1w, built from the source release by `scripts/build-openssl.sh` with a pinned SHA-256 checksum |
| Verifiers | Made by `openssl srp` in an srpvfile, one user per group |
| Runner | `ubuntu-latest` with the Go version from `go.mod` |

The test runs these cases:

| Case | Group | Cipher suite | Expected result |
| --- | --- | --- | --- |
| Sign-in | 2048 | AES-256 | Handshake succeeds |
| Sign-in | 3072 | AES-128 | Handshake succeeds |
| Sign-in | 4096 | AES-256 | Handshake succeeds |
| Sign-in | 8192 | AES-256 | Handshake succeeds |
| Small group allowed | 1024, with `MinGroupBits` 1024 | AES-256 | Handshake succeeds |
| Small group refused | 1024, default `MinGroupBits` | AES-256 | The client refuses the group |
| Wrong password | 2048 | AES-256 | The client error wraps `ErrWrongPassword` |
| Unknown username | None | AES-256 | The client error wraps `ErrUnknownUsername` |

For each successful handshake the test checks that:

* the connection uses TLS 1.2, the requested cipher suite and Extended Master Secret,
* `s_server` reports the same cipher suite under its OpenSSL name,
* application data passes in both directions,
* `ExportKeyingMaterial` returns the same 32 bytes that `s_server` exports with `-keymatexport`,
* the master secret in the client's key log appears in the key log of `s_server`.

The 1536 and 6144 bit groups and the 3DES cipher suite are not part of this test. No test runs an
OpenSSL client against the package's server.

## Running the test

```bash
make test-interop
```

This builds OpenSSL 1.1.1w under `bin/openssl-1.1.1` on first use and runs `TestOpenSSLServer`. The
build needs a C compiler, make, perl and curl. To test with another OpenSSL 1.1.1 binary, point
`SRPTLS_TEST_OPENSSL` at it:

```bash
SRPTLS_TEST_OPENSSL=/path/to/openssl go test -run TestOpenSSLServer -v .
```

Without `SRPTLS_TEST_OPENSSL` the test is skipped, so `make test` does not need OpenSSL.

## OpenSSL 3.0 and later

The test uses OpenSSL 1.1.1 because, as its comment records, `openssl s_server` from OpenSSL 3.0.22,
3.5.9, 3.6.5 and 4.0.3 closes the connection during its SRP user lookup, also with its own `s_client`.

`openssl s_client` from OpenSSL 3.0 onward has a bug in its `-srpuser` handling that discards the
`-srppass` password and signs in with an empty one
([openssl/openssl#32565](https://github.com/openssl/openssl/issues/32565)). The handshake then fails
like a wrong password. Test a server with OpenSSL 1.1.1 `s_client` or with a program that calls the
libssl SRP functions directly.
