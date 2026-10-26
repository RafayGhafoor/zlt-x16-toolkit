SHELL := /bin/bash
BIN   := zltx16
DIST  := dist

GOPATH_BIN := $(shell go env GOPATH)/bin
GARBLE     := $(GOPATH_BIN)/garble

# garble v0.18 needs Go >= 1.27. If a standalone SDK is present we prefer it,
# otherwise we ask the go command to fetch the toolchain.
GOSDK := $(HOME)/sdk/go1.27.0
ifeq ($(wildcard $(GOSDK)/bin/go),)
  GOBIN := go
  GOTOOLCHAIN_ENV := GOTOOLCHAIN=go1.27.0
else
  # garble shells out to whatever "go" is on PATH, so the SDK must be first.
  GOBIN := $(GOSDK)/bin/go
  GOTOOLCHAIN_ENV :=
  export PATH := $(GOSDK)/bin:$(PATH)
endif

# -s -w strips the symbol table and DWARF; -buildid= removes the build id.
LDFLAGS := -s -w -buildid=

.PHONY: all help test test-go test-py vet fmt seal build build-enc build-all verify-enc clean tools deps

all: test build-enc

help:
	@echo "make test        run Go + Python tests"
	@echo "make build       plain readable build (dev only)"
	@echo "make seal        regenerate the sealed literals (internal/zlt/sealed_gen.go)"
	@echo "make build-enc   ENCRYPTED build (AES-GCM sealed literals)"
	@echo "make build-garble  alternative: garble -literals (NOTE: macOS AV deletes it)"
	@echo "make build-all   encrypted builds for every target OS/arch"
	@echo "make verify-enc  prove the sensitive strings are gone"
	@echo "make clean       remove dist/"

# --- tests ------------------------------------------------------------------
test: test-go test-py

test-go:
	go vet ./...
	go test ./... -count=1

test-py:
	cd python && python3 -m unittest -v test_zltx16_unlock

vet:
	go vet ./...

fmt:
	gofmt -l -w ./cmd ./internal

# --- tooling ----------------------------------------------------------------
tools: garble-install

garble-install:
	@test -x $(GARBLE) || (cd /tmp && $(GOBIN) install mvdan.cc/garble@v0.18.0)

deps:
	$(GOBIN) mod download
	@command -v upx >/dev/null || echo "note: upx not found (optional compression skipped)"

# --- builds -----------------------------------------------------------------
build:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 $(GOBIN) build -trimpath -ldflags "$(LDFLAGS)" \
		-o=$(DIST)/$(BIN)-plain ./cmd/zltx16
	@echo "built $(DIST)/$(BIN)-plain  (READABLE - dev only, do not distribute)"

# The default encrypted build. tools/genseal rewrites internal/zlt/sealed_gen.go
# with AES-256-GCM ciphertext for the sensitive literals (CGI path, payload
# template, default credentials), so the shipped binary contains no readable
# endpoints, payload text or passwords.
#
# This is obfuscation, not cryptography: the key is in the binary. It defeats
# `strings`/`grep` - which is the realistic threat for a support bundle or a
# binary that ends up in a customer's hands.
seal:
	$(GOBIN) run ./tools/genseal

build-enc: seal
	@mkdir -p $(DIST)
	CGO_ENABLED=0 $(GOBIN) build -trimpath -ldflags "$(LDFLAGS)" \
		-o=$(DIST)/$(BIN) ./cmd/zltx16
	@if command -v upx >/dev/null && [ "$$(uname -s)" != "Darwin" ]; then \
		upx --best --quiet $(DIST)/$(BIN); fi
	@echo "built $(DIST)/$(BIN)  (sealed literals)"
	@shasum -a 256 $(DIST)/$(BIN) 2>/dev/null || sha256sum $(DIST)/$(BIN)

# Optional, stronger output. NOTE: on macOS with an active AV/EDR agent the
# resulting binary is usually quarantined and deleted within seconds
# (observed here: every -literals build, all GOOS/GOARCH). Run it on Linux.
build-garble: garble-install
	@mkdir -p $(DIST)
	CGO_ENABLED=0 $(GOTOOLCHAIN_ENV) $(GARBLE) -literals -tiny -seed=random build \
		-trimpath -ldflags="$(LDFLAGS)" -o=$(DIST)/$(BIN)-garble ./cmd/zltx16

PLATFORMS := darwin/arm64 darwin/amd64 linux/arm64 linux/amd64 linux/arm windows/amd64
build-all: seal
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=$(DIST)/$(BIN)-$$os-$$arch; \
		[ "$$os" = "windows" ] && out=$$out.exe; \
		echo "--> $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GOBIN) build \
			-trimpath -ldflags="$(LDFLAGS)" -o=$$out ./cmd/zltx16 || exit 1; \
	done
	@ls -lh $(DIST)

# Proves the obfuscation worked. "sha256" is deliberately NOT asserted:
# it is a stdlib package name (crypto/sha256) and carries no secret. Uses grep -a because macOS `strings` refuses to
# read binaries that a security agent has flagged.
verify-enc:
	@$(MAKE) --no-print-directory build-enc >/dev/null
	@echo "--- literals that MUST be absent from $(DIST)/$(BIN) ---"
	@fail=0; \
	for s in "cgi-bin/http.cgi" "busybox telnetd" "NO_AUTH" "192.168.3.1" \
	         "superadmin" "telnetd" "RequestCmd"; do \
		if LC_ALL=C grep -a -q -F "$$s" $(DIST)/$(BIN) 2>/dev/null; then \
			echo "  LEAK   $$s"; fail=1; \
		else echo "  ok     $$s"; fi; \
	done; \
	echo "--- control: the plain build must still contain them ---"; \
	LC_ALL=C grep -a -q -F "cgi-bin/http.cgi" $(DIST)/$(BIN)-plain 2>/dev/null \
		&& echo "  ok     plain build leaks as expected" \
		|| echo "  note   build the plain binary first (make build)"; \
	exit $$fail

clean:
	rm -rf $(DIST)
