.PHONY: build install clean test docker package

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)

build:
	@echo "Building fogbot $(VERSION)..."
	go build -ldflags "$(LDFLAGS)" -o fogbot ./cmd/fogbot
	@echo "Build complete: fogbot"

install: build
	@echo "Installing to package structure..."
	mkdir -p usr/local/bin
	cp fogbot usr/local/bin/
	chmod +x usr/local/bin/fogbot
	@echo "Installation complete"

clean:
	@echo "Cleaning build artifacts..."
	rm -f fogbot
	rm -f usr/local/bin/fogbot
	@echo "Clean complete"

test:
	@echo "Running tests..."
	go test -v ./...

# Docker targets
docker-build:
	@echo "Building Docker image..."
	docker-compose build

docker-up: docker-build
	@echo "Starting fogbot in Docker..."
	docker-compose up -d

docker-down:
	@echo "Stopping fogbot Docker container..."
	docker-compose down

docker-logs:
	docker-compose logs -f fogbot

docker-shell:
	docker-compose exec fogbot /bin/bash

# Test with proper paths
test-cli: build
	@echo "Testing CLI commands..."
	@export FOGBOT_SKILLS_AVAILABLE=$(PWD)/etc/fogbot/skills-available; \
	export FOGBOT_SKILLS_ENABLED=$(PWD)/etc/fogbot/skills-enabled; \
	export FOGBOT_CONFIG=$(PWD)/etc/fogbot/config.yaml; \
	export FOGBOT_STATE_DIR=/tmp/fogbot-test; \
	./fogbot skill list

# Package (requires ian tool)
package: build install
	@echo "Creating Debian package..."
	ian build
	@echo "Package created"

help:
	@echo "Fogbot Makefile targets:"
	@echo "  build         - Build the fogbot binary"
	@echo "  install       - Install binary to package structure"
	@echo "  clean         - Remove build artifacts"
	@echo "  test          - Run Go tests"
	@echo "  test-cli      - Test CLI with environment variables"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-up     - Start fogbot in Docker Compose"
	@echo "  docker-down   - Stop Docker Compose"
	@echo "  docker-logs   - Show Docker logs"
	@echo "  docker-shell  - Open shell in Docker container"
	@echo "  package       - Build Debian package with ian"
	@echo "  help          - Show this help message"
