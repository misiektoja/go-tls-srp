# Contributing

## Development

The Makefile runs the same checks as CI:

```bash
make test           # go vet and the tests under the race detector
make lint           # golangci-lint
make actionlint     # lint the GitHub Actions workflows
make test-interop   # the client against OpenSSL 1.1.1w s_server
make govulncheck    # known vulnerabilities that reach the code
make gitleaks       # leaked credentials in the tree and the history
make help           # every target
```

The recipes use the Go version from `go.mod` and download it when needed. Pinned tools are installed under `bin/` on first use. Building OpenSSL needs a C compiler, make and perl.

Pull requests to `main` and `dev` must pass the tests, lint, the OpenSSL interop test, govulncheck and gitleaks.

## Following Go releases

Commit `b52d68c` holds `crypto/tls` from Go 1.27.2 unchanged. The kept files are `alert.go`, `cipher_suites.go`, `common.go`, `conn.go`, `handshake_messages.go`, `handshake_server.go`, `prf.go` and `tls.go`. `handshake_client.go` follows the TLS 1.2 part of Go's client. The SRP code is in `srp.go` and `groups_rfc5054.go`.

The Upstream Go workflow runs two checks on every push and weekly:

* `make upstream-check` fails when a kept file of `UPSTREAM_GO_VERSION` (Go 1.27.2) changed in the installed Go release, which is the newest stable release in CI. Set `UPSTREAM_CANDIDATE=go1.28.0` to compare with a specific release. When it fails, port the changes that affect the TLS 1.2 client or server, the CBC record layer or the handshake message parsing. Then raise `UPSTREAM_GO_VERSION` to the release you ported.
* `make go-version-check` fails when a newer patch release of the Go minor in `go.mod` exists. Raise the `go` directive in `go.mod` to that release so the checks run against a current standard library.

`make upstream-check` prints the diff. To see it for one file:

```bash
git diff --no-index "$(go1.27.2 env GOROOT)/src/crypto/tls/conn.go" "$(go env GOROOT)/src/crypto/tls/conn.go"
```

## Releases

[RELEASE_NOTES.md](RELEASE_NOTES.md) has one section per version. Run the release check on `main`, then push a version tag:

```bash
VERSION=v0.1.0 make release-check
git tag -s v0.1.0 -m 'v0.1.0'
git push origin main v0.1.0
```

The release check tests an export of `HEAD` imported from a separate module, which catches untracked and local-only files. A version tag reachable from `main` starts the release workflow. It repeats the check, builds source archives, an SBOM and checksums, attests their provenance and creates a draft release with the release notes section as its description. Review the draft and publish it. Do not draft a release in the GitHub UI. That creates the tag and the workflow refuses to rebuild a published release.
