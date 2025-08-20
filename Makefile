# Binary name
BINARY_NAME=conscan

# Go related variables
GOBASE := $(shell pwd)
GOBIN  := $(GOBASE)/bin
GOFILES := $(wildcard *.go)

.PHONY: all build run clean test

all: build

## Build the Go binary
build: fmt vet ## Build manager binary.
	@echo ">> Building $(BINARY_NAME)..."
	@mkdir -p $(GOBIN)
	@go build -o $(GOBIN)/$(BINARY_NAME) .

## Run the app
run: build
	@$(GOBIN)/$(BINARY_NAME)

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: run
run: fmt vet ## Run a controller from your host.
	go run main.go

## Run tests
test:
	@echo ">> Running tests..."
	@go test ./... -v

## Remove generated files
clean:
	@echo ">> Cleaning up..."
	@rm -rf $(GOBIN)

## Cross compile (Linux example)
build-linux:
	@echo ">> Building for linux/amd64..."
	@GOOS=linux GOARCH=amd64 go build -o $(GOBIN)/$(BINARY_NAME)-linux .

## Cross compile (Mac example)
build-mac:
	@echo ">> Building for darwin/amd64..."
	@GOOS=darwin GOARCH=amd64 go build -o $(GOBIN)/$(BINARY_NAME)-mac .
