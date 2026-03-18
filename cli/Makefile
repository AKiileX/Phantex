# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w \
	-X github.com/AKiileX/Phantex/cli/cmd.Version=$(VERSION) \
	-X github.com/AKiileX/Phantex/cli/cmd.Commit=$(COMMIT) \
	-X github.com/AKiileX/Phantex/cli/cmd.BuildDate=$(DATE)

.PHONY: build install test lint clean all cross

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/phantex .

install:
	go install -ldflags "$(LDFLAGS)" .

test:
	go test ./... -v -count=1

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

# Cross-compile for Linux, macOS, Windows
cross:
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/phantex-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/phantex-linux-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/phantex-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/phantex-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/phantex-windows-amd64.exe .
