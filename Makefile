.PHONY: test e2e build clean deps dev-up dev-down

deps:
	docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -w /app golang:1.21-alpine go mod tidy
	docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -w /app golang:1.21-alpine go mod download

build:
	docker compose build

test:
	docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -v go-build-cache:/root/.cache/go-build -w /app -e CGO_ENABLED=1 golang:1.21 go test -v -race -coverprofile=coverage.out ./...
	docker run --rm -v $(PWD):/app -v go-mod-cache:/go/pkg/mod -w /app golang:1.21-alpine go tool cover -html=coverage.out -o coverage.html

e2e:
	@echo "🚀 Running dockerized end-to-end tests..."
	docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from e2e-test
	docker compose -f docker-compose.test.yml down -v

dev-up:
	docker compose up --build -d

dev-down:
	docker compose down -v

clean:
	rm -rf bin/ data/ coverage.out coverage.html
	docker compose down -v --remove-orphans
	docker compose -f docker-compose.test.yml down -v --remove-orphans

clean-cache:
	docker volume rm go-mod-cache go-build-cache 2>/dev/null || true

help:
	@echo "Available targets:"
	@echo "  deps       - Download dependencies"
	@echo "  build      - Build Docker images"
	@echo "  test       - Run unit tests with coverage"
	@echo "  e2e        - Run dockerized end-to-end tests"
	@echo "  dev-up     - Start development environment"
	@echo "  dev-down   - Stop development environment"
	@echo "  clean      - Clean build artifacts and containers"
	@echo "  clean-cache - Remove Go module and build cache volumes"