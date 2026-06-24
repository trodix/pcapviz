// Package bootstrap is the shared composition root for pcapviz. It wires the
// concrete adapters behind the application core's ports so the two entrypoints
// — the web-server binary (cmd/pcapviz) and the standalone desktop binary
// (cmd/pcapviz-desktop) — build the exact same stack.
package bootstrap

import (
	"net/http"

	httpadapter "pcapviz/internal/adapter/http"
	"pcapviz/internal/adapter/memstore"
	"pcapviz/internal/adapter/pcap"
	"pcapviz/internal/app"
	"pcapviz/internal/observ"
	"pcapviz/internal/port"
)

// NewService builds the application service backed by the in-memory store and
// the pcap decoder, logging through the given logger.
func NewService(logger *observ.Logger) *app.Service {
	return app.New(memstore.New(), pcap.NewDecoder(), logger.Slog())
}

// opener returns how to turn a file path into a packet source (keeps the HTTP
// adapter decoupled from the pcap adapter).
func opener() httpadapter.Opener {
	return func(path string) (port.PacketSource, error) { return pcap.Open(path) }
}

// Handler builds the HTTP handler (REST API + embedded UI + logs API) for the
// service.
func Handler(svc *app.Service, logger *observ.Logger) http.Handler {
	return httpadapter.NewHandler(svc, opener(), logger)
}

// Preload loads a capture file into the service at startup. A path of "" is a
// no-op.
func Preload(svc *app.Service, path string) error {
	if path == "" {
		return nil
	}
	src, err := pcap.Open(path)
	if err != nil {
		return err
	}
	return svc.Load(src)
}
