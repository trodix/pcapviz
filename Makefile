# pcapviz — portable single-binary pcap/pcapng web analyzer.
#
# `make build` produces a self-contained binary for the host OS with the Svelte
# UI embedded. `make dist` cross-compiles Windows + Linux binaries.

GO        ?= go
BIN       ?= pcapviz
PKG       := ./cmd/pcapviz
DIST      := internal/adapter/http/dist
LDFLAGS   := -s -w
# CGO disabled => fully static, trivially portable binary (pure-Go pcap reader).
export CGO_ENABLED = 0

.PHONY: all build web deps test clean dist run

all: build

## web: install deps (first run) and build the embedded frontend.
web:
	cd web && [ -d node_modules ] || npm install
	cd web && npm run build

## build: frontend + single binary for the host OS into bin/.
build: web
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/$(BIN) $(PKG)

## dist: cross-compiled binaries for Linux and Windows (amd64).
dist: web
	GOOS=linux   GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o bin/$(BIN)-linux-amd64    $(PKG)
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o bin/$(BIN)-windows-amd64.exe $(PKG)

## test: run the Go unit tests.
test:
	$(GO) test ./...

## run: build then run, opening the browser (optionally PCAP=path to preload).
run: build
	./bin/$(BIN) $(PCAP)

## clean: remove build artifacts.
clean:
	rm -rf bin web/node_modules
	find $(DIST) -mindepth 1 ! -name index.html -delete
