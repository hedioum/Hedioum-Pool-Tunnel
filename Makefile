# Hedioum Dynamic Pool Tunnel - Build Automation
# This Makefile automates the cross-compilation for Linux environments.

BINARY_NAME=hedioum-tunnel
MAIN_PATH=./cmd/hedioum
BUILD_DIR=bin

# Linker flags:
# -s disables symbol table
# -w disables DWARF generation
# These reduce binary size by ~50% without affecting runtime functionality.
LDFLAGS=-ldflags="-s -w"

.PHONY: all build-linux build-linux-arm64 clean fmt deps

all: build-linux build-linux-arm64

build-linux: deps fmt
	@echo "Building highly optimized Linux AMD64 static binary..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "[✓] AMD64 Build complete! Static binary is ready at: $(BUILD_DIR)/$(BINARY_NAME)"

build-linux-arm64: deps fmt
	@echo "Building highly optimized Linux ARM64 static binary..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-arm64 $(MAIN_PATH)
	@echo "[✓] ARM64 Build complete! Static binary is ready at: $(BUILD_DIR)/$(BINARY_NAME)-arm64"

clean:
	@echo "Cleaning up build artifacts..."
	rm -rf $(BUILD_DIR)/
	@echo "[✓] Clean complete."

fmt:
	@echo "Formatting Go source code..."
	go fmt ./...

deps:
	@echo "Resolving and downloading Go modules..."
	go mod tidy