.PHONY: test test-verbose build clean deps dev-up dev-down coverage e2e e2e-url

deps:
	docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -w /app golang:1.23-alpine go mod tidy
	docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -w /app golang:1.23-alpine go mod download

build:
	docker compose build

test:
	@echo "🧪 Running tests (failures only)..."
	@docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -v go-build-cache:/root/.cache/go-build -w /app -e CGO_ENABLED=1 golang:1.23 go test -v -race -coverprofile=coverage.out ./... 2>&1 | grep -E "(FAIL|^FAIL|^\?\?\?|--- FAIL|coverage:|^ok )" || true
	@echo "✅ Test run complete. Use 'make test-verbose' for full output."

test-verbose:
	docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -v go-build-cache:/root/.cache/go-build -w /app -e CGO_ENABLED=1 golang:1.23 go test -v -race -coverprofile=coverage.out ./...

coverage: test
	@echo "📊 Generating coverage reports..."
	docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -w /app golang:1.23-alpine go tool cover -html=coverage.out -o coverage.html
	docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -w /app golang:1.23-alpine go tool cover -func=coverage.out
	@echo "📄 HTML coverage report: coverage.html"
	@echo "📈 Coverage summary:"
	@docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -w /app golang:1.23-alpine go tool cover -func=coverage.out | tail -1

e2e:
	@echo "🚀 Running end-to-end tests..."
	timeout 60s docker compose -f docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from e2e-client || (echo "❌ E2E tests timed out or failed"; docker compose -f docker-compose.e2e.yml down -v; exit 1)
	docker compose -f docker-compose.e2e.yml down -v

e2e-url:
	@echo "🎯 Running end-to-end tests with tunnel URL capture and HTTP validation..."
	timeout 90s ./test/run-e2e-with-url-capture.sh

dev-up:
	docker compose up --build -d

dev-down:
	docker compose down -v

clean:
	rm -rf bin/ coverage.out coverage.html
	docker compose down -v --remove-orphans
	docker compose -f docker-compose.e2e.yml down -v --remove-orphans

clean-cache:
	docker volume rm go-mod-cache go-build-cache 2>/dev/null || true

help:
	@echo "Available targets:"
	@echo "  deps         - Download dependencies"
	@echo "  build        - Build Docker images"
	@echo "  test         - Run unit tests (failures only output)"
	@echo "  test-verbose - Run unit tests with full verbose output"
	@echo "  coverage     - Generate and display detailed coverage reports"
	@echo "  e2e          - Run end-to-end tests"
	@echo "  e2e-url      - Run end-to-end tests with URL capture and HTTP validation"
	@echo "  dev-up       - Start development environment"
	@echo "  dev-down     - Stop development environment"
	@echo "  clean        - Clean build artifacts and containers"
	@echo "  clean-cache  - Remove Go module and build cache volumes"