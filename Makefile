# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# GO_VERSION is the go directive in go.mod. The release check's consumer module declares it. Every
# recipe runs with exactly that toolchain, which is the one CI installs through go-version-file, so a
# newer local Go cannot change what the checks see. golangci-lint analyses the standard library of the
# toolchain in use, and a toolchain newer than the linter understands makes it crash.
GO_VERSION := $(shell awk '$$1 == "go" && $$2 ~ /^[0-9]/ { print $$2; exit }' go.mod)
export GOTOOLCHAIN := go$(GO_VERSION)

.PHONY: all
all: test

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt-check
fmt-check: ## Fail when a tracked Go file is not gofmt formatted.
	@unformatted=$$(gofmt -l $$(git ls-files '*.go')); \
	if [ -n "$$unformatted" ]; then echo "not gofmt formatted:"; echo "$$unformatted"; exit 1; fi

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: tidy-check
tidy-check: ## Fail when go.mod or go.sum is not tidy.
	go mod tidy -diff

.PHONY: test
test: vet ## Run the tests under the race detector.
	go test -race -count=1 ./...

# OPENSSL_PREFIX holds the OpenSSL 1.1.1 build that test-interop runs against.
OPENSSL_PREFIX ?= $(LOCALBIN)/openssl-1.1.1

# The -list check fails a renamed test, which -run would otherwise skip without an error.
.PHONY: test-interop
test-interop: openssl ## Run the client against OpenSSL 1.1.1 s_server. Builds OpenSSL on first use.
	@go test -list '^TestOpenSSLServer$$' . | grep -x TestOpenSSLServer >/dev/null || { echo "error: TestOpenSSLServer is missing"; exit 1; }
	SRPTLS_TEST_OPENSSL="$(OPENSSL_PREFIX)/bin/openssl" go test -race -count=1 -v -run '^TestOpenSSLServer$$' .

##@ Release

# VERSION names the release tag, for example v0.1.0. Every artifact is named after it.
VERSION ?=
# Artifacts without a release, such as a local SBOM run, are named after the commit instead.
SBOM_VERSION := $(if $(VERSION),$(VERSION),$(shell git rev-parse --short HEAD))
SOURCE_ZIP = dist/go-tls-srp-$(VERSION)-source.zip
SOURCE_TAR_GZ = dist/go-tls-srp-$(VERSION)-source.tar.gz
SBOM_FILE = dist/go-tls-srp-$(SBOM_VERSION)-sbom.cdx.json
RELEASE_CHECKSUMS = dist/go-tls-srp-$(VERSION)_SHA256SUMS.txt
# RELEASE_CHECK_DIR holds the export and the consumer module. It must not exist yet.
RELEASE_CHECK_DIR ?= $(CURDIR)/.cache/release-check

.PHONY: require-version
require-version:
	@test -n "$(VERSION)" || { echo "Set VERSION, for example VERSION=v0.1.0" >&2; exit 1; }

# A go.work above the checkout or the check directory would replace the module's own requirements.
release-check sbom: export GOWORK = off
.PHONY: release-check
release-check: ## Build, vet and test an export of HEAD and import it from a separate module. Set VERSION to check the release notes heading.
	@if grep -q '^replace ' go.mod; then echo "error: go.mod has a replace directive"; exit 1; fi
	@if [ -n "$(VERSION)" ]; then \
		version="$(VERSION)"; version="$${version#v}"; \
		grep -q "^## \[$$version\] - " RELEASE_NOTES.md || { echo "error: RELEASE_NOTES.md has no heading for $$version"; exit 1; }; \
		if grep -qi '^## \[Unreleased' RELEASE_NOTES.md; then echo "error: RELEASE_NOTES.md still has an Unreleased section"; exit 1; fi; \
	fi
	@check="$(RELEASE_CHECK_DIR)"; \
	if [ -e "$$check" ]; then echo "error: $$check exists, move it aside first"; exit 1; fi; \
	mkdir -p "$$check/export" "$$check/consumer"; \
	git archive --format=tar HEAD | tar -x -C "$$check/export"; \
	cd "$$check/export" && go mod verify && go build ./... && go vet ./... && go test -count=1 ./...; \
	cd "$$check/consumer" && printf 'module example.com/consumer\n\ngo %s\n\nrequire github.com/misiektoja/go-tls-srp v0.0.0\n\nreplace github.com/misiektoja/go-tls-srp => ../export\n' "$(GO_VERSION)" > go.mod; \
	printf 'package main\n\nimport (\n\t"log"\n\n\tsrptls "github.com/misiektoja/go-tls-srp"\n)\n\nfunc main() {\n\t_, err := srptls.Listen("tcp", "127.0.0.1:0", &srptls.Config{})\n\tlog.Println(err)\n}\n' > main.go; \
	go mod tidy && go build ./... && go run .; \
	echo "release check passed for $$(git -C "$(CURDIR)" rev-parse --short HEAD)"

.PHONY: release-body
release-body: require-version ## Extract the RELEASE_NOTES.md section of VERSION into dist/release-body.md.
	@mkdir -p dist
	@version="$(VERSION)"; awk -v want="## [$${version#v}]" 'index($$0, want) == 1 { found = 1; next } found && /^## \[/ { exit } found { print }' RELEASE_NOTES.md | sed '/./,$$!d' > dist/release-body.md
	@grep -q '[^[:space:]]' dist/release-body.md || { echo "error: RELEASE_NOTES.md has no section for $(VERSION)" >&2; exit 1; }
	@echo "Wrote dist/release-body.md"

.PHONY: sbom
sbom: cyclonedx-gomod ## Generate a CycloneDX software bill of materials for the module. Set VERSION for a release.
	mkdir -p dist
	"$(CYCLONEDX_GOMOD)" mod -licenses -json -output "$(SBOM_FILE)" .
	@echo "Wrote $(SBOM_FILE)"

.PHONY: release-source-archives
release-source-archives: require-version ## Archive the complete tagged source tree as ZIP and tar. Set VERSION.
	mkdir -p dist
	git archive --format=zip --output "$(SOURCE_ZIP)" "$(VERSION)"
	git archive --format=tar.gz --output "$(SOURCE_TAR_GZ)" "$(VERSION)"

.PHONY: release-checksums
release-checksums: release-source-archives ## Write SHA-256 checksums for the source archives and the SBOM. Set VERSION.
	@test -f "$(SBOM_FILE)" || { echo "Run sbom with the same VERSION first, $(SBOM_FILE) is missing" >&2; exit 1; }
	cd dist && shasum -a 256 "$(notdir $(SBOM_FILE))" "$(notdir $(SOURCE_ZIP))" "$(notdir $(SOURCE_TAR_GZ))" | tee "$(notdir $(RELEASE_CHECKSUMS))"

##@ Checks

.PHONY: lint
lint: golangci-lint ## Run golangci-lint.
	"$(GOLANGCI_LINT)" run

.PHONY: lint-config
lint-config: golangci-lint ## Verify the golangci-lint configuration.
	"$(GOLANGCI_LINT)" config verify

.PHONY: actionlint
actionlint: actionlint-tool ## Lint the GitHub Actions workflows.
	"$(ACTIONLINT)"

.PHONY: govulncheck
govulncheck: govulncheck-tool ## Report known vulnerabilities that reach the module or its dependencies.
	"$(GOVULNCHECK)" ./...

# GITLEAKS_LOG_OPTS selects the history the commit scan walks.
GITLEAKS_LOG_OPTS ?= --full-history --all

.PHONY: gitleaks
gitleaks: gitleaks-tool ## Scan the working tree and the commit history for leaked credentials.
# Excluded artifact paths must not contain tracked files.
	@test -z "$$(git ls-files local .cache bin dist)" || { echo "error: tracked files are excluded from the gitleaks scan by .gitleaks.toml"; exit 1; }
	"$(GITLEAKS)" dir . --config .gitleaks.toml --redact --no-banner
	"$(GITLEAKS)" git . --config .gitleaks.toml --redact --no-banner --log-opts="$(GITLEAKS_LOG_OPTS)"

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
GOVULNCHECK ?= $(LOCALBIN)/govulncheck
GITLEAKS ?= $(LOCALBIN)/gitleaks
ACTIONLINT ?= $(LOCALBIN)/actionlint
CYCLONEDX_GOMOD ?= $(LOCALBIN)/cyclonedx-gomod

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.14.0
GOVULNCHECK_VERSION ?= v1.7.0
GITLEAKS_VERSION ?= v8.30.1
ACTIONLINT_VERSION ?= v1.7.12
CYCLONEDX_GOMOD_VERSION ?= v1.11.0

.PHONY: golangci-lint
golangci-lint: | $(LOCALBIN) ## Download golangci-lint locally if necessary.
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: govulncheck-tool
govulncheck-tool: | $(LOCALBIN) ## Download govulncheck locally if necessary.
	$(call go-install-tool,$(GOVULNCHECK),golang.org/x/vuln/cmd/govulncheck,$(GOVULNCHECK_VERSION))

.PHONY: gitleaks-tool
gitleaks-tool: | $(LOCALBIN) ## Download gitleaks locally if necessary.
	$(call go-install-tool,$(GITLEAKS),github.com/zricethezav/gitleaks/v8,$(GITLEAKS_VERSION))

.PHONY: actionlint-tool
actionlint-tool: | $(LOCALBIN) ## Download actionlint locally if necessary.
	$(call go-install-tool,$(ACTIONLINT),github.com/rhysd/actionlint/cmd/actionlint,$(ACTIONLINT_VERSION))

.PHONY: openssl
openssl: | $(LOCALBIN) ## Build OpenSSL 1.1.1 for test-interop if necessary.
	scripts/build-openssl.sh "$(OPENSSL_PREFIX)"

.PHONY: cyclonedx-gomod
cyclonedx-gomod: | $(LOCALBIN) ## Download cyclonedx-gomod locally if necessary.
	$(call go-install-tool,$(CYCLONEDX_GOMOD),github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod,$(CYCLONEDX_GOMOD_VERSION))

# go-install-tool installs a package at a pinned version under a versioned directory and points the
# unversioned tool path at it, so a version bump installs the new tool instead of keeping the old one.
# $1 - tool path, $2 - package path, $3 - version
define go-install-tool
@dir="$(LOCALBIN)/.tools/$(notdir $(1))@$(3)"; \
if [ ! -x "$$dir/$(notdir $(1))" ]; then \
	echo "Downloading $(2)@$(3)"; \
	mkdir -p "$$dir"; \
	GOBIN="$$dir" go install "$(2)@$(3)"; \
fi; \
ln -sfn "$$dir/$(notdir $(1))" "$(1)"
endef
