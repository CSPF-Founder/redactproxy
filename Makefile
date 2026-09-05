BINARY := redactproxy
CMD := ./cmd/redactproxy
DIST := dist

.PHONY: build test vet lint check race fuzz dist clean install

# Default: build a binary for the current platform into ./bin.
build:
	mkdir -p bin
	go build -o bin/$(BINARY) $(CMD)

test:
	go test ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

# Deliberately not part of `check`: golangci-lint is the only tool here
# not in the Go distribution, and `check` gates `dist`, so folding it in
# would fail a release build on a machine that doesn't have it. CI runs
# it as its own job. Config in .golangci.yml.
#
# Install it with the same toolchain this module targets. golangci-lint
# embeds a Go type-checker at build time and refuses to run against a
# module targeting a newer Go than it was built with, so a distro package
# or an older release tarball can fail where `go install` from this
# checkout succeeds. CI pins the matching version in ci.yml.
#   go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
lint:
	golangci-lint run ./...

# Everything a pre-release check should run, using only what ships with
# Go. CI additionally runs `lint` and govulncheck as separate jobs.
check: vet race

# Open-ended mutation search, on top of the seed corpus `make test`
# already runs. Not part of `check` for that reason.
#
# Sequential on purpose: `go test -fuzz` spawns one worker per core, so
# two targets at once thrash CPU and memory. Don't make this parallel.
#
# Targets come from `go test -list`, not a list kept here: a
# hand-maintained one silently stops covering a target the day someone
# adds one, and a missing test looks exactly like a passing one.
FUZZTIME ?= 60s
FUZZ ?= Fuzz
fuzz:
	@set -e; \
	for pkg in $$(go list ./internal/...); do \
	  for fn in $$(go test $$pkg -list "^$(FUZZ)" 2>/dev/null | grep "^Fuzz" || true); do \
	    echo "=== $$fn ($$pkg, $(FUZZTIME))"; \
	    go test $$pkg -run '^$$' -fuzz "^$$fn$$" -fuzztime $(FUZZTIME); \
	  done; \
	done

# Cross-compiled binaries for team distribution: one static binary per
# platform, stripped (-s -w). Nothing debugs a binary handed to a team
# member, so losing the symbol table costs nothing; Delve and gdb stop
# working against these.
#
# main.version is stamped from the nearest tag, since a stripped binary
# has no other way to answer `redactproxy version` in a bug report.
# Override for a release build off a detached tag:
# `make dist VERSION=v1.2.3`.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
LDFLAGS_DIST := -ldflags="-s -w -X main.version=$(VERSION)"

dist: check
	mkdir -p $(DIST)
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS_DIST) -o $(DIST)/$(BINARY)-linux-amd64     $(CMD)
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS_DIST) -o $(DIST)/$(BINARY)-linux-arm64     $(CMD)
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS_DIST) -o $(DIST)/$(BINARY)-darwin-amd64    $(CMD)
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS_DIST) -o $(DIST)/$(BINARY)-darwin-arm64    $(CMD)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS_DIST) -o $(DIST)/$(BINARY)-windows-amd64.exe $(CMD)

# Build and drop the binary directly onto $PATH for local use.
install:
	go build -o $$(go env GOPATH)/bin/$(BINARY) $(CMD)

clean:
	rm -rf bin $(DIST)
