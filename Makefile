# Development entry points. Everything here is a thin wrapper over the Go
# toolchain, so nothing is required beyond a Go installation.

BINARY      := bin/mcp-server
PKG         := ./cmd/server
VERSION     ?= 1.0.0
IMAGE       ?= company-mcp-server
INSPECTOR   := @modelcontextprotocol/inspector
FUZZTIME    ?= 30s

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the server binary into bin/
	@mkdir -p bin
	go build -trimpath -ldflags="-s -w" -o $(BINARY) $(PKG)

.PHONY: run-stdio
run-stdio: build ## Run the server on the stdio transport
	MCP_TRANSPORT=stdio ./$(BINARY)

.PHONY: run-http
run-http: build ## Run the server on Streamable HTTP, loopback only, no auth
	@echo "listening on http://127.0.0.1:8080  (auth disabled - loopback only)"
	@echo "  GET /          endpoint directory"
	@echo "  GET /healthz   liveness      GET /readyz  readiness"
	@echo "  GET /metrics   Prometheus    POST /mcp    MCP endpoint"
	MCP_TRANSPORT=http MCP_HTTP_ADDR=127.0.0.1:8080 MCP_ALLOW_INSECURE_HTTP=true ./$(BINARY)

.PHONY: check-config
check-config: build ## Validate the environment and exit without serving
	./$(BINARY) -check-config

.PHONY: env
env: ## Create .env from .env.example if it does not exist
	@if [ -f .env ]; then \
		echo ".env already exists; leaving it alone"; \
	else \
		cp .env.example .env && echo "created .env from .env.example - edit it, then: make check-config"; \
	fi

.PHONY: test
test: ## Run the full test suite
	go test ./...

.PHONY: test-race
test-race: ## Run the test suite under the race detector
	go test -race ./...

.PHONY: fuzz
fuzz: ## Run each fuzz target for FUZZTIME (default 30s)
	@for target in FuzzCustomerID FuzzResourceURI FuzzSearchInput FuzzCursor FuzzNotificationInput FuzzScopeParsing; do \
		echo "--- $$target"; \
		go test -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZTIME) ./tests/fuzz/ || exit 1; \
	done

.PHONY: bench
bench: ## Run the benchmarks
	go test -run '^$$' -bench . -benchmem ./tests/bench/

.PHONY: cover
cover: ## Run tests and report coverage of the internal packages
	go test -coverpkg=./internal/... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format the module
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if anything is unformatted
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: vuln
vuln: ## Scan for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: staticcheck
staticcheck: ## Run staticcheck
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

.PHONY: check
check: fmt-check vet test-race vuln ## Everything CI runs, locally

.PHONY: inspect
inspect: build ## Open the MCP Inspector against the stdio server
	npx $(INSPECTOR) ./$(BINARY)

.PHONY: inspect-http
inspect-http: ## Open the MCP Inspector against a running HTTP server
	npx $(INSPECTOR)

.PHONY: docker
docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

.PHONY: docker-scan
docker-scan: docker ## Scan the container image for vulnerabilities
	trivy image --severity HIGH,CRITICAL --exit-code 1 $(IMAGE):$(VERSION)

.PHONY: sbom
sbom: ## Generate a CycloneDX SBOM for the module
	go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest mod -json -output sbom.json .

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	go mod tidy

.PHONY: clean
clean: ## Remove build output
	rm -rf bin coverage.out sbom.json
