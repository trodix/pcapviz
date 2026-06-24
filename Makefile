# pcapviz — portable pcap/pcapng analyzer.
#
# Two front-ends share the same Go core (internal/bootstrap):
#   * web server  (cmd/pcapviz)         -> opens the UI in a browser; pure-Go,
#                                          fully static, trivially cross-compiled.
#   * desktop app (cmd/pcapviz-desktop) -> native OS webview window (WebKitGTK on
#                                          Linux, WebView2 on Windows), light on RAM.
#
# `make build`/`make dist`        -> web-server binaries.
# `make desktop`/`make desktop-windows` -> standalone desktop binaries.

GO        ?= go
BIN       ?= pcapviz
PKG       := ./cmd/pcapviz
DESKTOP   := ./cmd/pcapviz-desktop
DIST      := internal/adapter/http/dist
LDFLAGS   := -s -w
# Pure-Go web server => static binary. CGO is re-enabled only for the Linux
# desktop target (which links WebKitGTK).
export CGO_ENABLED = 0

.PHONY: all build web test clean dist run desktop desktop-windows desktop-all

all: build

## web: install deps (first run) and build the embedded frontend.
web:
	cd web && [ -d node_modules ] || npm install
	cd web && npm run build

## build: web-server binary for the host OS into bin/.
build: web
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/$(BIN) $(PKG)

## dist: cross-compiled web-server binaries (Linux + Windows amd64).
dist: web
	GOOS=linux   GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o bin/$(BIN)-linux-amd64       $(PKG)
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o bin/$(BIN)-windows-amd64.exe  $(PKG)

## desktop: native Linux desktop app (needs gcc + webkit2gtk-4.1 + gtk3).
desktop: web
	CGO_ENABLED=1 $(GO) build -ldflags "$(LDFLAGS)" -o bin/$(BIN)-desktop $(DESKTOP)

## desktop-windows: Windows desktop app, cross-compiled from Linux (WebView2, no CGO).
desktop-windows: web
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS) -H windowsgui" -o bin/$(BIN)-desktop-windows-amd64.exe $(DESKTOP)

## desktop-all: Linux + Windows desktop binaries.
desktop-all: desktop desktop-windows

## test: run the Go unit tests.
test:
	$(GO) test ./...

## run: build then run the web server (optionally PCAP=path to preload).
run: build
	./bin/$(BIN) $(PCAP)

## clean: remove build artifacts (keeps the committed built frontend).
clean:
	rm -rf bin web/node_modules
