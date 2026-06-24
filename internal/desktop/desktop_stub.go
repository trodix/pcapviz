//go:build !windows && (!linux || !cgo)

package desktop

import "errors"

// Run is the fallback used on unsupported platforms, or on Linux when built
// without cgo. Desktop mode requires Linux (CGO_ENABLED=1, WebKitGTK) or Windows.
func Run(url, title string, width, height int) error {
	return errors.New("desktop mode requires Linux (built with CGO_ENABLED=1 and WebKitGTK) or Windows; use the web-server binary instead")
}
