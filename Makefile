# Copyright The prometheus-mcp-fleet Authors.
# SPDX-License-Identifier: Apache-2.0

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

MODULE      := github.com/jacoknapp/prometheus-mcp-fleet
BIN_DIR     := bin
COMPONENTS  := hub spoke

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# SOURCE_DATE_EPOCH keeps rebuilds byte-identical; see docs/development.md.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || date -u +%s)
DATE    ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

GO_BUILD_FLAGS := -trimpath -ldflags '$(LDFLAGS)'

REGISTRY   ?= ghcr.io/jacoknapp/prometheus-mcp-fleet
PLATFORMS  ?= linux/amd64,linux/arm64
COVER_FILE := coverage.out

##@ General

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Build

.PHONY: build
build: $(addprefix build-,$(COMPONENTS)) ## Build every binary into ./bin.

.PHONY: build-%
build-%: ## Build a single component, e.g. `make build-hub`.
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$* ./cmd/$*

.PHONY: install
install: ## Install both binaries into GOBIN.
	CGO_ENABLED=0 go install $(GO_BUILD_FLAGS) ./cmd/...

.PHONY: clean
clean: ## Remove build and coverage artifacts.
	rm -rf $(BIN_DIR) dist $(COVER_FILE) coverage.html

##@ Code generation

.PHONY: generate
generate: proto ## Run every generator.

.PHONY: proto
proto: ## Regenerate protobuf/gRPC code from api/proto.
	buf lint
	buf generate
	gofmt -w internal/gen

.PHONY: proto-breaking
proto-breaking: ## Fail if the wire contract broke against origin/main.
	buf breaking --against '.git#branch=origin/main'

##@ Quality

.PHONY: fmt
fmt: ## Format all Go source.
	gofmt -w $$(git ls-files '*.go' | grep -v '^internal/gen/')

.PHONY: fmt-check
fmt-check: ## Fail if any Go source is unformatted.
	@out=$$(gofmt -l $$(git ls-files '*.go' | grep -v '^internal/gen/')); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint.
	golangci-lint run --timeout=5m

.PHONY: test
test: ## Run unit tests with the race detector.
	go test -race -covermode=atomic -coverprofile=$(COVER_FILE) ./...

.PHONY: test-short
test-short: ## Run fast unit tests only.
	go test -short ./...

.PHONY: cover
cover: test ## Show per-package coverage.
	go tool cover -func=$(COVER_FILE) | tail -40

.PHONY: cover-html
cover-html: test ## Write an HTML coverage report.
	go tool cover -html=$(COVER_FILE) -o coverage.html

.PHONY: fuzz
fuzz: ## Run every fuzz target briefly.
	@for pkg in $$(go list ./... ); do \
		for fn in $$(go test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
			echo "==> $$pkg $$fn"; go test -run '^$$' -fuzz "^$$fn$$" -fuzztime=30s $$pkg; \
		done; \
	done

.PHONY: vuln
vuln: ## Check dependencies for known vulnerabilities.
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: tidy
tidy: ## Tidy and verify go.mod.
	go mod tidy
	go mod verify

.PHONY: check
check: fmt-check vet lint test ## Everything CI runs on a pull request.

##@ Container images

.PHONY: image-%
image-%: ## Build a single component image locally, e.g. `make image-hub`.
	docker build \
		--build-arg COMPONENT=$* \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
		-t $(REGISTRY)/$*:$(VERSION) -f Dockerfile .

.PHONY: images
images: $(addprefix image-,$(COMPONENTS)) ## Build every component image locally.

##@ Helm

.PHONY: helm-lint
helm-lint: ## Lint both charts against every ci/ values file.
	@for chart in charts/*/; do \
		echo "==> $$chart"; \
		helm lint --strict "$$chart"; \
		for values in "$$chart"ci/*.yaml; do \
			[ -e "$$values" ] || continue; \
			echo "    values: $$values"; \
			helm lint --strict "$$chart" -f "$$values"; \
		done; \
	done

.PHONY: helm-template
helm-template: ## Render both charts with default values.
	@for chart in charts/*/; do helm template test "$$chart" >/dev/null && echo "ok $$chart"; done

.PHONY: helm-unittest
helm-unittest: ## Run helm-unittest suites.
	helm unittest charts/prometheus-mcp-hub charts/prometheus-mcp-spoke

.PHONY: helm-docs
helm-docs: ## Regenerate chart READMEs from values.yaml.
	helm-docs --chart-search-root=charts

##@ End to end

.PHONY: e2e
e2e: ## Run the kind-based end-to-end suite (needs kind + docker).
	go test -tags e2e -timeout 20m ./test/e2e/...
