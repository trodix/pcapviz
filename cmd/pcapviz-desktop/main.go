// Command pcapviz-desktop runs pcapviz as a standalone desktop application: it
// starts the HTTP server in-process on a random localhost port and displays the
// UI in a native OS webview window (WebKitGTK on Linux, WebView2 on Windows).
// No browser, no bundled Chromium — much lighter on RAM than Electron.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"

	"pcapviz/internal/bootstrap"
	"pcapviz/internal/desktop"
)

func main() {
	width := flag.Int("width", 1280, "window width")
	height := flag.Int("height", 860, "window height")
	flag.Parse()

	svc := bootstrap.NewService()
	if err := bootstrap.Preload(svc, flag.Arg(0)); err != nil {
		log.Fatalf("preload %s: %v", flag.Arg(0), err)
	}

	// Listen on a random free port bound to loopback only.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	url := "http://" + ln.Addr().String()

	srv := &http.Server{Handler: bootstrap.Handler(svc)}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	// Blocks until the window is closed; then the process exits.
	if err := desktop.Run(url, "pcapviz", *width, *height); err != nil {
		log.Fatal(err)
	}
}
