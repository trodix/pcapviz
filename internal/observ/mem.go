package observ

import "runtime"

// MemInfo is a snapshot of the process's memory usage, exposed to the UI.
type MemInfo struct {
	// RSS is the resident set size in bytes (physical memory used by the
	// process, as a system monitor would report it). 0 when unavailable on the
	// platform; callers can fall back to Sys.
	RSS uint64 `json:"rss"`
	// HeapAlloc is the bytes of allocated, still-reachable Go heap objects.
	HeapAlloc uint64 `json:"heapAlloc"`
	// Sys is the total bytes of memory the Go runtime obtained from the OS.
	Sys uint64 `json:"sys"`
	// NumGoroutine is the current number of goroutines.
	NumGoroutine int `json:"numGoroutine"`
}

// ReadMem samples the current process memory usage.
func ReadMem() MemInfo {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return MemInfo{
		RSS:          processRSS(),
		HeapAlloc:    m.HeapAlloc,
		Sys:          m.Sys,
		NumGoroutine: runtime.NumGoroutine(),
	}
}
