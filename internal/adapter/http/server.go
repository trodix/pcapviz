// Package http is the driving (inbound) adapter: it exposes the application use
// cases as a small REST API and serves the embedded Svelte frontend. It depends
// on the application core and the port interfaces, not on concrete adapters —
// the way to open a capture file is injected as an Opener.
package http

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"pcapviz/internal/app"
	"pcapviz/internal/observ"
	"pcapviz/internal/port"
)

//go:embed all:dist
var distFS embed.FS

// Opener turns a local file path into a packet source. Injected by main so this
// adapter stays decoupled from the pcap adapter.
type Opener func(path string) (port.PacketSource, error)

// Handler bundles the API routes and the static frontend.
type Handler struct {
	svc  *app.Service
	open Opener
	log  *observ.Logger
}

// NewHandler builds the HTTP handler tree, wrapped with panic-recovery and
// request-logging middleware.
func NewHandler(svc *app.Service, open Opener, logger *observ.Logger) http.Handler {
	h := &Handler{svc: svc, open: open, log: logger}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/status", h.status)
	mux.HandleFunc("GET /api/packets", h.listPackets)
	mux.HandleFunc("GET /api/packets/{num}", h.packetDetail)
	mux.HandleFunc("GET /api/stats", h.stats)
	mux.HandleFunc("GET /api/conversations", h.conversations)
	mux.HandleFunc("POST /api/open", h.openPath)
	mux.HandleFunc("POST /api/upload", h.upload)

	// Observability endpoints (see server_logs.go).
	mux.HandleFunc("GET /api/logs", h.getLogs)
	mux.HandleFunc("GET /api/logs/level", h.getLogLevel)
	mux.HandleFunc("POST /api/logs/level", h.setLogLevel)
	mux.HandleFunc("GET /api/crashes", h.listCrashes)
	mux.HandleFunc("GET /api/crashes/{name}", h.getCrash)
	mux.HandleFunc("GET /api/meminfo", h.meminfo)
	mux.HandleFunc("POST /api/tls/decrypt", h.tlsDecrypt)

	sub, _ := fs.Sub(distFS, "dist")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return h.middleware(mux)
}

// statusRecorder captures the response status for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// middleware recovers panics (so one bad request can't take down the server)
// and logs each request at debug level.
func (h *Handler) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				h.log.Slog().Error("panic recovered in HTTP handler",
					"method", r.Method, "path", r.URL.Path,
					"panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sr, r)
		// Skip high-frequency polling endpoints to avoid self-generated noise.
		if !strings.HasPrefix(r.URL.Path, "/api/logs") && r.URL.Path != "/api/meminfo" {
			h.log.Slog().Debug("request",
				"method", r.Method, "path", r.URL.Path,
				"status", sr.status, "took", time.Since(start).String())
		}
	})
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"count":  h.svc.Count(),
		"loaded": h.svc.Count() > 0,
	})
}

func (h *Handler) listPackets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	page, err := h.svc.ListPackets(q.Get("filter"), offset, limit)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (h *Handler) packetDetail(w http.ResponseWriter, r *http.Request) {
	num, err := strconv.Atoi(r.PathValue("num"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid packet number"))
		return
	}
	d, err := h.svc.PacketDetail(num)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (h *Handler) stats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.svc.Stats())
}

func (h *Handler) conversations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.svc.Conversations())
}

func (h *Handler) openPath(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path == "" {
		writeErr(w, http.StatusBadRequest, errors.New("missing path"))
		return
	}
	h.loadFrom(w, body.Path)
}

func (h *Handler) upload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("missing file field"))
		return
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "pcapviz-*.pcap")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	tmp.Close()
	_ = hdr
	h.loadFrom(w, tmp.Name())
}

func (h *Handler) loadFrom(w http.ResponseWriter, path string) {
	src, err := h.open(path)
	if err != nil {
		h.log.Slog().Warn("open capture failed", "path", path, "error", err.Error())
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := h.svc.Load(src); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": h.svc.Count()})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
