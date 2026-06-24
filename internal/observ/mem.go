package observ

import "runtime"

// MemInfo is a snapshot of the process's memory usage, exposed to the UI.
type MemInfo struct {
	// RSS is the resident set size in bytes of the core (Go) process, as a
	// system monitor would report it. 0 when unavailable on the platform.
	RSS uint64 `json:"rss"`
	// RenderRSS is the summed RSS of descendant processes — in desktop mode the
	// native WebView's render/network processes (the web-rendering cost). 0 in
	// server mode (the browser is a separate, unrelated process).
	RenderRSS uint64 `json:"renderRSS"`
	// TotalRSS is RSS + RenderRSS.
	TotalRSS uint64 `json:"totalRSS"`
	// HeapAlloc is the bytes of allocated, still-reachable Go heap objects.
	HeapAlloc uint64 `json:"heapAlloc"`
	// Sys is the total bytes of memory the Go runtime obtained from the OS.
	Sys uint64 `json:"sys"`
	// NumGoroutine is the current number of goroutines.
	NumGoroutine int `json:"numGoroutine"`
}

// ReadMem samples the current process (and descendant) memory usage.
func ReadMem() MemInfo {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	self := processRSS()
	render := childrenRSS()
	return MemInfo{
		RSS:          self,
		RenderRSS:    render,
		TotalRSS:     self + render,
		HeapAlloc:    m.HeapAlloc,
		Sys:          m.Sys,
		NumGoroutine: runtime.NumGoroutine(),
	}
}
