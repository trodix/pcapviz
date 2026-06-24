// Package desktop opens a native OS webview window pointed at a local URL,
// giving pcapviz a standalone desktop mode that uses far less RAM than Electron
// (no bundled Chromium): WebKitGTK on Linux, WebView2 on Windows.
//
// The OS-specific implementations live in build-tagged files and all expose the
// same entrypoint:
//
//	func Run(url, title string, width, height int) error
//
//   - Linux (cgo): GTK3 + WebKitGTK 4.1 — built natively (CGO_ENABLED=1).
//   - Windows: github.com/jchv/go-webview2 (pure Go) — cross-compiles from Linux.
//   - Other / linux-without-cgo: a stub returning an explanatory error.
package desktop
