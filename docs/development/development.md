# Development

How to build, check and change the library. Contribution rules are in
[CONTRIBUTING.md](https://github.com/misiektoja/go-tls-srp/blob/main/CONTRIBUTING.md).

## Prerequisites

* Go at the version `go.mod` declares. Every Make target except `upstream-check` runs with exactly
  that toolchain, which Go downloads on first use when the installed version differs.
* A C compiler, make, perl and curl for `make test-interop`, which downloads and builds OpenSSL 1.1.1w.
* Python 3 with the pinned MkDocs dependencies for the documentation site, installed by
  `make docs-deps`. CI uses Python 3.13.

Linters and other tools are downloaded into `bin/` at pinned versions by the Make targets that need
them.

## Repository layout

| Path | Content |
| --- | --- |
| root package `srptls` | The library. [Architecture](../architecture.md) describes the files |
| `example_test.go` | The package examples, which the documentation site includes |
| `scripts/build-openssl.sh` | Builds the OpenSSL 1.1.1w command line tool for the interop test |
| `docs/` | This site |

## Common commands

```bash
make test           # go vet and the tests under the race detector
make lint           # golangci-lint
make actionlint     # lint the GitHub Actions workflows
make test-interop   # the client against OpenSSL 1.1.1w s_server
make govulncheck    # known vulnerabilities that reach the code
make gitleaks       # leaked credentials in the tree and the history
make docs-build     # strict MkDocs build
make help           # every target
```

`make fmt-check` fails when a tracked Go file is not gofmt formatted and `make tidy-check` when
`go.mod` or `go.sum` is not tidy. Pull requests to `main` and `dev` must pass the tests, lint, the
OpenSSL interop test, govulncheck and gitleaks.

## Following Go releases

Most of the package is `crypto/tls` from Go 1.27.2. `alert.go`, `cipher_suites.go`, `common.go`,
`conn.go`, `handshake_messages.go`, `handshake_server.go`, `prf.go` and `tls.go` are the kept files.
The Upstream Go workflow runs two checks on every push and pull request to `dev` and `main` and weekly:

* `make upstream-check` fails when a kept file changed between `UPSTREAM_GO_VERSION` (1.27.2) and the
  installed Go release, which CI makes the newest stable release. Set `UPSTREAM_CANDIDATE=go1.28.0`
  to compare with a specific release. When it fails, port the changes that affect the TLS 1.2 client
  or server, the CBC record layer or the handshake message parsing, then raise
  `UPSTREAM_GO_VERSION` in the Makefile to the release you ported.
* `make go-version-check` fails when a newer patch release of the Go minor version in `go.mod`
  exists. Raise the `go` directive to that release.

`make upstream-check` prints the diff. To see it for one file:

```bash
git diff --no-index "$(GOTOOLCHAIN=go1.27.2 go env GOROOT)/src/crypto/tls/conn.go" "$(go env GOROOT)/src/crypto/tls/conn.go"
```

## Documentation

The site is built with MkDocs and the Material theme from `docs/` and `mkdocs.yml`. Set `PYTHON`
when the MkDocs toolchain lives in a virtual environment:

```bash
make docs-deps PYTHON=.venv/bin/python
make docs-serve PYTHON=.venv/bin/python
```

* Go code on the pages comes from `example_test.go` through named snippet sections, which start and
  end with `--8<--` marker comments. `go test` compiles every example and runs those with an
  `// Output:` comment, so the code on the site cannot drift from the library. Keep the marker
  comments when you edit the examples.
* `make docs-build` runs with `--strict`, so a broken link, a missing anchor, a missing snippet or a
  page absent from the navigation fails the build.
* `docs/requirements.txt` pins every package by version and SHA-256 hash, including the transitive
  ones. `make docs-deps` installs it with `--require-hashes`. To change a version, edit
  `docs/requirements.in` and run `make docs-requirements`, which needs
  [pip-tools](https://pypi.org/project/pip-tools/) in the `PYTHON` environment. Dependabot updates
  the compiled file the same way.

The Documentation workflow runs the same build on every change to the site sources and publishes
the site from `main` to the `gh-pages` branch. The build runs with a read-only token and hands the
site to a separate publish job as an artifact, so the only job that can write to the repository runs
no code from PyPI or from the checkout.

Package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-tls-srp) comes
from the Go doc comments. User-facing behavior changes belong in both places.
