package http

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pcapviz/internal/observ"
)

// getLogs returns recent log entries at or above ?level= (default info), most
// recent ?limit= kept (default 500). With ?format=text the logs are returned as
// a downloadable plain-text attachment, handy to share a bug report.
func (h *Handler) getLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	level := q.Get("level")
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 500
	}
	entries := h.log.Entries(level, limit)

	if q.Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="pcapviz-logs.txt"`)
		var b strings.Builder
		for _, e := range entries {
			b.WriteString(e.Time.Format(time.RFC3339))
			b.WriteString(" [" + e.Level + "] ")
			b.WriteString(e.Message)
			for k, v := range e.Attrs {
				b.WriteString(" " + k + "=")
				b.WriteString(toString(v))
			}
			b.WriteByte('\n')
		}
		_, _ = w.Write([]byte(b.String()))
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *Handler) getLogLevel(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"level": h.log.Level(), "debug": h.log.Debug()})
}

// setLogLevel toggles debug capture at runtime: {"debug": true|false}.
func (h *Handler) setLogLevel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Debug bool `json:"debug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	h.log.SetDebug(body.Debug)
	h.log.Slog().Info("debug logging toggled", "debug", body.Debug)
	writeJSON(w, http.StatusOK, map[string]any{"level": h.log.Level(), "debug": h.log.Debug()})
}

func (h *Handler) listCrashes(w http.ResponseWriter, r *http.Request) {
	reports, err := h.log.CrashReports()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if reports == nil {
		reports = []observ.CrashInfo{} // serialize as [] not null
	}
	writeJSON(w, http.StatusOK, reports)
}

// meminfo returns the current process memory usage for the status bar.
func (h *Handler) meminfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, observ.ReadMem())
}

func (h *Handler) getCrash(w http.ResponseWriter, r *http.Request) {
	data, err := h.log.ReadCrash(r.PathValue("name"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(data)
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}
