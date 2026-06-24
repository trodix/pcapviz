// Command pcapviz runs the analyzer as a local web server and opens the UI in
// the default browser. For a standalone desktop window instead, see
// cmd/pcapviz-desktop. Both share the same stack via internal/bootstrap.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"pcapviz/internal/bootstrap"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "address to listen on")
	noBrowser := flag.Bool("no-browser", false, "do not open the browser on start")
	flag.Parse()

	svc := bootstrap.NewService()
	if err := bootstrap.Preload(svc, flag.Arg(0)); err != nil {
		log.Fatalf("preload %s: %v", flag.Arg(0), err)
	}
	if n := svc.Count(); n > 0 {
		log.Printf("loaded %d packets from %s", n, flag.Arg(0))
	}

	url := "http://" + *addr
	srv := &http.Server{Addr: *addr, Handler: bootstrap.Handler(svc)}
	go func() {
		fmt.Printf("pcapviz running at %s\n", url)
		if !*noBrowser {
			time.Sleep(300 * time.Millisecond)
			openBrowser(url)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
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
