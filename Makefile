.PHONY: build test docker-build docker-push clean deps lint

# Variables
BINARY_NAME := bridge
IMAGE_NAME := ghcr.io/nag-sh/jellyseerr-sso-bridge
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# Build
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/bridge

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/bridge

# Test
test:
	go test -v -race ./...

test-short:
	go test -v -short ./...

test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Lint
lint:
	golangci-lint run --timeout=5m

lint-fix:
	golangci-lint run --fix

# Docker
docker-build:
	docker build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

docker-push:
	docker push $(IMAGE_NAME):$(VERSION)
	docker push $(IMAGE_NAME):latest

# Development
run:
	go run ./cmd/bridge

# Clean
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Dependencies
deps:
	go mod download
	go mod tidy

