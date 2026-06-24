//go:build linux

package observ

import (
	"os"
	"strconv"
	"strings"
)

// processRSS returns this process's resident set size.
func processRSS() uint64 { return rssOfPid(os.Getpid()) }

// childrenRSS returns the summed RSS of all descendant processes. In desktop
// mode these are the WebView's render/network processes (the "web rendering"
// cost). In server mode there are none (the browser is a separate process), so
// this is 0.
func childrenRSS() uint64 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	children := map[int][]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ppid, ok := readPPID(pid); ok {
			children[ppid] = append(children[ppid], pid)
		}
	}

	var total uint64
	queue := append([]int{}, children[os.Getpid()]...)
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		total += rssOfPid(pid)
		queue = append(queue, children[pid]...)
	}
	return total
}

// rssOfPid reads /proc/<pid>/statm (field 2 = resident pages).
func rssOfPid(pid int) uint64 {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}

// readPPID parses the parent PID from /proc/<pid>/stat. The comm field can
// contain spaces and parentheses, so fields are read after the last ')'.
func readPPID(pid int) (int, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	s := string(data)
	close := strings.LastIndexByte(s, ')')
	if close < 0 {
		return 0, false
	}
	fields := strings.Fields(s[close+1:])
	// fields[0] = state, fields[1] = ppid
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, false
	}
	return ppid, true
}
