// Command pcapviz runs the analyzer as a local web server and opens the UI in
// the default browser. For a standalone desktop window instead, see
// cmd/pcapviz-desktop. Both share the same stack via internal/bootstrap.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"time"

	"pcapviz/internal/bootstrap"
	"pcapviz/internal/observ"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "address to listen on")
	noBrowser := flag.Bool("no-browser", false, "do not open the browser on start")
	debugLog := flag.Bool("debug", false, "enable debug logging from start")
	flag.Parse()

	logger := observ.New(2000, *debugLog)
	// Persist a crash report (only) if the main goroutine panics.
	defer crashGuard(logger)

	svc := bootstrap.NewService(logger)
	if err := bootstrap.Preload(svc, flag.Arg(0)); err != nil {
		fmt.Fprintf(os.Stderr, "preload %s: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}

	url := "http://" + *addr
	srv := &http.Server{Addr: *addr, Handler: bootstrap.Handler(svc, logger)}
	go func() {
		defer crashGuard(logger)
		logger.Slog().Info("server starting", "url", url)
		fmt.Printf("pcapviz running at %s\n", url)
		if !*noBrowser {
			time.Sleep(300 * time.Millisecond)
			openBrowser(url)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Slog().Error("server stopped", "error", err.Error())
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

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd, args = "open", []string{url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	if err := exec.Command(cmd, args...).Start(); err != nil {
		fmt.Fprintf(os.Stderr, "could not open browser: %v\n", err)
	}
}
