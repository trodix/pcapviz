// Command pcapviz is a portable, single-binary web analyzer for .pcap/.pcapng
// captures. It starts a local HTTP server, serves an embedded Svelte UI and
// exposes a small REST API. This file is the composition root: it wires the
// concrete adapters behind the application core's ports.
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

	httpadapter "pcapviz/internal/adapter/http"
	"pcapviz/internal/adapter/memstore"
	"pcapviz/internal/adapter/pcap"
	"pcapviz/internal/app"
	"pcapviz/internal/port"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "address to listen on")
	noBrowser := flag.Bool("no-browser", false, "do not open the browser on start")
	flag.Parse()

	// Wire the hexagon: in-memory store + pcap decoder behind the use cases.
	store := memstore.New()
	service := app.New(store, pcap.NewDecoder())

	// Inject how to open a capture file (keeps the HTTP adapter decoupled).
	opener := func(path string) (port.PacketSource, error) { return pcap.Open(path) }

	// Optional positional arg: preload a capture at startup.
	if path := flag.Arg(0); path != "" {
		src, err := pcap.Open(path)
		if err != nil {
			log.Fatalf("open %s: %v", path, err)
		}
		if err := service.Load(src); err != nil {
			log.Fatalf("load %s: %v", path, err)
		}
		log.Printf("loaded %d packets from %s", service.Count(), path)
	}

	handler := httpadapter.NewHandler(service, opener)
	url := "http://" + *addr

	srv := &http.Server{Addr: *addr, Handler: handler}
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
