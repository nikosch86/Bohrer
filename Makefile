.PHONY: test test-verbose test-quick test-pkg test-run test-match test-webui test-ssh test-proxy test-acme test-config test-certs test-logger build clean deps dev-up dev-down coverage coverage-check e2e lint fmt security deadcode build-tools all ci validate help check-go-version

# Use bash instead of sh for better compatibility
SHELL := /bin/bash

# Variables for consistency
REQUIRED_GO_VERSION := 1.24
DOCKER_COMPOSE_E2E := docker-compose.e2e.yml
COVERAGE_THRESHOLD := 85
TEST_TIMEOUT := 60s
E2E_TIMEOUT := 60s

# Check if go is installed and has the correct version
GO_VERSION_CHECK := $(shell go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/go//')
GO_MAJOR := $(shell echo $(GO_VERSION_CHECK) | cut -d. -f1)
GO_MINOR := $(shell echo $(GO_VERSION_CHECK) | cut -d. -f2)
REQUIRED_MAJOR := $(shell echo $(REQUIRED_GO_VERSION) | cut -d. -f1)
REQUIRED_MINOR := $(shell echo $(REQUIRED_GO_VERSION) | cut -d. -f2)

# Docker commands only for e2e tests
DOCKER_GO_RUN := docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -v go-build-cache:/root/.cache/go-build -w /app
DOCKER_GO_E2E := $(DOCKER_GO_RUN) -e CGO_ENABLED=1 golang:$(REQUIRED_GO_VERSION)

# Default target
all: check-go-version clean deps test coverage-check lint

# CI/CD target (uses docker for everything)
ci: deps test coverage-check lint e2e

# Check Go version
check-go-version:
	@if [ -z "$(GO_VERSION_CHECK)" ]; then \
		echo "❌ Go is not installed. Please install Go $(REQUIRED_GO_VERSION) or later"; \
		echo "   Visit https://golang.org/dl/ to download"; \
		exit 1; \
	fi
	@if [ "$(GO_MAJOR)" -lt "$(REQUIRED_MAJOR)" ] || \
	   ([ "$(GO_MAJOR)" -eq "$(REQUIRED_MAJOR)" ] && [ "$(GO_MINOR)" -lt "$(REQUIRED_MINOR)" ]); then \
		echo "❌ Go version $(GO_VERSION_CHECK) is too old. Required: $(REQUIRED_GO_VERSION) or later"; \
		echo "   Current: $(GO_VERSION_CHECK)"; \
		echo "   Visit https://golang.org/dl/ to download"; \
		exit 1; \
	fi
	@echo "✅ Go version $(GO_VERSION_CHECK) meets requirement (>= $(REQUIRED_GO_VERSION))"

deps: check-go-version
	@echo "📦 Downloading dependencies..."
	go mod tidy
	go mod download
	@echo "✅ Dependencies updated"

build:
	@echo "🔨 Building Docker images..."
	docker compose build

# Quick test without race detection for faster development
test-quick: check-go-version
	@echo "⚡ Running quick tests..."
	go test -short -coverprofile=coverage.out ./...
	@echo "✅ Quick tests complete"

test: check-go-version
	@echo "🧪 Running tests (failures only)..."
	@go test -v -race -timeout=$(TEST_TIMEOUT) -coverprofile=coverage.out ./... 2>&1 | grep -E "(FAIL|^FAIL|^\?\?\?|--- FAIL|coverage:|^ok )" || true
	@echo "✅ Test run complete. Use 'make test-verbose' for full output."

test-verbose: check-go-version
	@echo "🧪 Running verbose tests..."
	go test -v -race -timeout=$(TEST_TIMEOUT) -coverprofile=coverage.out ./...

# Selective testing targets
test-pkg: check-go-version
	@if [ -z "$(PKG)" ]; then \
		echo "❌ Usage: make test-pkg PKG=<package>"; \
		echo "   Example: make test-pkg PKG=./internal/webui"; \
		echo "   Example: make test-pkg PKG=./internal/webui,./internal/ssh"; \
		exit 1; \
	fi
	@echo "🧪 Running tests for package(s): $(PKG)..."
	@go test -v -race -timeout=$(TEST_TIMEOUT) $(shell echo $(PKG) | tr ',' ' ')

test-run: check-go-version
	@if [ -z "$(RUN)" ]; then \
		echo "❌ Usage: make test-run RUN=<test_pattern> [PKG=<package>]"; \
		echo "   Example: make test-run RUN=TestWebUIAuthentication"; \
		echo "   Example: make test-run RUN=TestWebUI PKG=./internal/webui"; \
		exit 1; \
	fi
	@echo "🧪 Running tests matching pattern: $(RUN) in $(if $(PKG),$(PKG),all packages)..."
	@go test -v -race -timeout=$(TEST_TIMEOUT) -run="$(RUN)" $(if $(PKG),$(PKG),./...)

test-match: check-go-version
	@if [ -z "$(MATCH)" ]; then \
		echo "❌ Usage: make test-match MATCH=<pattern> [PKG=<package>]"; \
		echo "   Example: make test-match MATCH=Auth"; \
		echo "   Example: make test-match MATCH=Integration PKG=./internal/webui"; \
		exit 1; \
	fi
	@echo "🧪 Running tests containing pattern: $(MATCH) in $(if $(PKG),$(PKG),all packages)..."
	@go test -v -race -timeout=$(TEST_TIMEOUT) -run=".*$(MATCH).*" $(if $(PKG),$(PKG),./...)

# Package-specific test shortcuts
test-webui: check-go-version
	@echo "🌐 Running WebUI tests..."
	@go test -v -race -timeout=$(TEST_TIMEOUT) ./internal/webui

test-ssh: check-go-version
	@echo "🔑 Running SSH tests..."
	@go test -v -race -timeout=$(TEST_TIMEOUT) ./internal/ssh

test-proxy: check-go-version
	@echo "🌐 Running Proxy tests..."
	@go test -v -race -timeout=$(TEST_TIMEOUT) ./internal/proxy

test-acme: check-go-version
	@echo "🔒 Running ACME tests..."
	@go test -v -race -timeout=$(TEST_TIMEOUT) ./internal/acme

test-config: check-go-version
	@echo "⚙️  Running Config tests..."
	@go test -v -race -timeout=$(TEST_TIMEOUT) ./internal/config

test-certs:
	@echo "📜 Running Certificates tests..."
	@$(DOCKER_GO_FULL) go test -v -race -timeout=$(TEST_TIMEOUT) ./internal/certs

test-logger:
	@echo "📝 Running Logger tests..."
	@$(DOCKER_GO_FULL) go test -v -race -timeout=$(TEST_TIMEOUT) ./internal/logger

coverage: test
	@echo "📊 Generating coverage reports..."
	$(DOCKER_GO_ALPINE) go tool cover -html=coverage.out -o coverage.html
	$(DOCKER_GO_ALPINE) go tool cover -func=coverage.out
	@echo "📄 HTML coverage report: coverage.html"
	@echo "📈 Coverage summary:"
	@$(DOCKER_GO_ALPINE) go tool cover -func=coverage.out | tail -1

coverage-check: test
	@echo "🎯 Checking coverage threshold ($(COVERAGE_THRESHOLD)%)..."
	@COVERAGE=$$($(DOCKER_GO_ALPINE) go tool cover -func=coverage.out | tail -1 | grep -o '[0-9.]\+%' | tr -d '%'); \
	if [ $$(echo "$$COVERAGE >= $(COVERAGE_THRESHOLD)" | bc -l) -eq 1 ]; then \
		echo "✅ Coverage $$COVERAGE% meets threshold $(COVERAGE_THRESHOLD)%"; \
	else \
		echo "❌ Coverage $$COVERAGE% below threshold $(COVERAGE_THRESHOLD)%"; \
		exit 1; \
	fi

lint: build-tools
	@echo "🔍 Running linters..."
	$(DOCKER_TOOLS) golangci-lint run ./... || $(DOCKER_GO_ALPINE) go vet ./...
	@echo "✅ Linting complete"

fmt:
	@echo "🎨 Formatting code..."
	$(DOCKER_GO_ALPINE) go fmt ./...
	@echo "✅ Code formatted"

security: check-go-version
	@echo "🔒 Running security checks..."
	@echo "  🛡️  Running govulncheck for known vulnerabilities..."
	@which govulncheck > /dev/null 2>&1 && govulncheck ./... || echo "   govulncheck not installed, skipping"
	@echo "✅ Security checks complete"

deadcode: check-go-version
	@echo "🧹 Detecting dead code..."
	@which deadcode > /dev/null 2>&1 && deadcode -test ./... || echo "   deadcode not installed, skipping"
	@echo "✅ Dead code analysis complete"

e2e:
	@echo "🚀 Running end-to-end tests..."
	@./test/e2e.sh

validate: deps build test coverage-check lint security deadcode
	@echo "✅ All validation checks passed"

dev-up:
	@echo "🚀 Starting development environment..."
	docker compose up --build -d
	@echo "✅ Development environment started"

dev-down:
	@echo "🛑 Stopping development environment..."
	docker compose down -v
	@echo "✅ Development environment stopped"

clean:
	@echo "🧹 Cleaning up..."
	rm -rf bin/ coverage.out coverage.html
	docker compose down -v --remove-orphans
	docker compose -f $(DOCKER_COMPOSE_E2E) down -v --remove-orphans
	@echo "✅ Cleanup complete"

clean-all: clean clean-cache
	@echo "🧹 Deep cleaning..."
	docker system prune -f
	@echo "✅ Deep cleanup complete"

clean-cache:
	@echo "🗑️  Removing cache volumes..."
	docker volume rm go-mod-cache go-build-cache 2>/dev/null || true
	@echo "✅ Cache volumes removed"

help:
	@echo "🚀 Bohrer-go Development Commands"
	@echo ""
	@echo "📋 Main Targets:"
	@echo "  all          - Run complete validation pipeline (clean, deps, test, coverage-check, lint)"
	@echo "  ci           - CI/CD pipeline (deps, test, coverage-check, lint, e2e)"
	@echo "  validate     - Quick validation (deps, build, test, coverage-check, lint, security, deadcode)"
	@echo ""
	@echo "🏗️  Build & Dependencies:"
	@echo "  check-go-version - Verify Go version meets requirements (>= $(REQUIRED_GO_VERSION))"
	@echo "  deps         - Download and tidy Go dependencies"
	@echo "  build        - Build all Docker images"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test-quick   - Run quick tests without race detection"
	@echo "  test         - Run unit tests with race detection (failures only)"
	@echo "  test-verbose - Run unit tests with full verbose output"
	@echo "  coverage     - Generate and display detailed coverage reports"
	@echo "  coverage-check - Check if coverage meets $(COVERAGE_THRESHOLD)% threshold"
	@echo ""
	@echo "🎯 Selective Testing:"
	@echo "  test-pkg PKG=<path>     - Run tests for specific package(s)"
	@echo "  test-run RUN=<pattern>  - Run tests matching specific function pattern"
	@echo "  test-match MATCH=<text> - Run tests containing specific text"
	@echo ""
	@echo "📦 Package-Specific Tests:"
	@echo "  test-webui   - Run WebUI tests (./internal/webui)"
	@echo "  test-ssh     - Run SSH tests (./internal/ssh)"
	@echo "  test-proxy   - Run Proxy tests (./internal/proxy)"
	@echo "  test-acme    - Run ACME tests (./internal/acme)"
	@echo "  test-config  - Run Config tests (./internal/config)"
	@echo "  test-certs   - Run Certificates tests (./internal/certs)"
	@echo "  test-logger  - Run Logger tests (./internal/logger)"
	@echo ""
	@echo "🔍 Code Quality:"
	@echo "  lint         - Run Go linters (golangci-lint)"
	@echo "  fmt          - Format Go code"
	@echo "  security     - Run security analysis (govulncheck)"
	@echo "  deadcode     - Detect unused code"
	@echo ""
	@echo "🌐 End-to-End Testing:"
	@echo "  e2e          - Run complete E2E test suite (uses Docker)"
	@echo ""
	@echo "🔧 Development:"
	@echo "  dev-up       - Start development environment"
	@echo "  dev-down     - Stop development environment"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  clean        - Clean build artifacts and containers"
	@echo "  clean-cache  - Remove Go module and build cache volumes"
	@echo "  clean-all    - Deep clean including Docker system prune"
	@echo ""
	@echo "💡 Common Workflows:"
	@echo "  make all           # Complete validation pipeline"
	@echo "  make test-quick    # Quick development testing"
	@echo "  make validate      # Pre-commit validation"
	@echo "  make e2e           # Full end-to-end testing"
	@echo ""
	@echo "🎯 Selective Testing Examples:"
	@echo "  make test-webui                                    # Test WebUI package only"
	@echo "  make test-pkg PKG=./internal/webui                # Same as test-webui"
	@echo "  make test-pkg PKG='./internal/webui,./internal/ssh' # Test multiple packages"
	@echo "  make test-run RUN=TestWebUIAuthentication          # Run specific test function"
	@echo "  make test-run RUN=TestWebUI PKG=./internal/webui   # Run pattern in specific package"
	@echo "  make test-match MATCH=Auth                         # Run tests containing 'Auth'"
	@echo "  make test-match MATCH=Integration                  # Run integration tests only"