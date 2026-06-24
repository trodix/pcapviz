//go:build linux && cgo

package desktop

/*
#cgo pkg-config: gtk+-3.0 webkit2gtk-4.1
#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include <stdlib.h>

static void pcapviz_run_webview(const char* title, const char* url, int width, int height) {
    gtk_init(0, NULL);
    GtkWidget* window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), title);
    gtk_window_set_default_size(GTK_WINDOW(window), width, height);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    WebKitWebView* webview = WEBKIT_WEB_VIEW(webkit_web_view_new());
    gtk_container_add(GTK_CONTAINER(window), GTK_WIDGET(webview));
    webkit_web_view_load_uri(webview, url);

    gtk_widget_grab_focus(GTK_WIDGET(webview));
    gtk_widget_show_all(window);
    gtk_main();
}
*/
import "C"
import "unsafe"

// Run opens a GTK window hosting a WebKitGTK view at url and blocks until the
// window is closed.
func Run(url, title string, width, height int) error {
	ctitle := C.CString(title)
	curl := C.CString(url)
	defer C.free(unsafe.Pointer(ctitle))
	defer C.free(unsafe.Pointer(curl))
	C.pcapviz_run_webview(ctitle, curl, C.int(width), C.int(height))
	return nil
}
