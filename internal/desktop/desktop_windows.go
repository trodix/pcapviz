//go:build windows

package desktop

import (
	"errors"

	webview2 "github.com/jchv/go-webview2"
)

// Run opens a WebView2-backed window at url and blocks until it is closed.
// Requires the Microsoft Edge WebView2 runtime, which ships with Windows 10/11.
func Run(url, title string, width, height int) error {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  title,
			Width:  uint(width),
			Height: uint(height),
		},
	})
	if w == nil {
		return errors.New("failed to create webview (is the WebView2 runtime installed?)")
	}
	defer w.Destroy()
	w.Navigate(url)
	w.Run()
	return nil
}
