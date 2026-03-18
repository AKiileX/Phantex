# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w

.PHONY: build install test testacc lint clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/terraform-provider-phantex .

install: build
	mkdir -p ~/.terraform.d/plugins/registry.terraform.io/AKiileX/phantex/$(VERSION)/linux_amd64
	cp bin/terraform-provider-phantex ~/.terraform.d/plugins/registry.terraform.io/AKiileX/phantex/$(VERSION)/linux_amd64/

test:
	go test ./... -v -count=1

testacc:
	TF_ACC=1 go test ./internal/provider/ -v -count=1 -timeout 10m

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
