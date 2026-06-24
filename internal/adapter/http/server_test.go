package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"pcapviz/internal/observ"
)

func TestRecoveryMiddleware(t *testing.T) {
	logger := observ.New(10, false)
	h := &Handler{log: logger}

	panicky := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom in handler")
	})
	srv := httptest.NewServer(h.middleware(panicky))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	// The panic must have been logged at error level rather than crashing.
	if got := len(logger.Entries("error", 0)); got == 0 {
		t.Error("panic was not logged at error level")
	}
}
