// Command pcapviz-desktop runs pcapviz as a standalone desktop application: it
// starts the HTTP server in-process on a random localhost port and displays the
// UI in a native OS webview window (WebKitGTK on Linux, WebView2 on Windows).
// No browser, no bundled Chromium — much lighter on RAM than Electron.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime/debug"

	"pcapviz/internal/bootstrap"
	"pcapviz/internal/desktop"
	"pcapviz/internal/observ"
)

func main() {
	width := flag.Int("width", 1280, "window width")
	height := flag.Int("height", 860, "window height")
	debugLog := flag.Bool("debug", false, "enable debug logging from start")
	flag.Parse()

	logger := observ.New(2000, *debugLog)
	defer crashGuard(logger)

	svc := bootstrap.NewService(logger)
	if err := bootstrap.Preload(svc, flag.Arg(0)); err != nil {
		fmt.Fprintf(os.Stderr, "preload %s: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}

	// Listen on a random free port bound to loopback only.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logger.Slog().Error("listen failed", "error", err.Error())
		os.Exit(1)
	}
	url := "http://" + ln.Addr().String()

	srv := &http.Server{Handler: bootstrap.Handler(svc, logger)}
	go func() {
		defer crashGuard(logger)
		logger.Slog().Info("desktop server starting", "url", url)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Slog().Error("server stopped", "error", err.Error())
		}
	}()

	// Blocks until the window is closed; then the process exits.
	if err := desktop.Run(url, "pcapviz", *width, *height); err != nil {
		logger.Slog().Error("desktop window failed", "error", err.Error())
		os.Exit(1)
	}
}

// crashGuard recovers a panic, writes a crash report and exits non-zero.
func crashGuard(logger *observ.Logger) {
	if rec := recover(); rec != nil {
		path, _ := logger.WriteCrashReport(rec, debug.Stack())
		fmt.Fprintf(os.Stderr, "FATAL: %v\ncrash report written to %s\n", rec, path)
		os.Exit(1)
	}
}
