// Command preview-emails starts a local HTTP server to preview email templates in the browser.
//
// Usage:
//
//	go run ./cmd/preview-emails
//
// Then open http://localhost:9090 in your browser.
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/oluwasemilore/aegis/internal/email"
)

func main() {
	renderer, err := email.NewTemplateRenderer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load templates: %v\n", err)
		os.Exit(1)
	}

	// Serve the preview page.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "internal/email/preview.html")
	})

	// Render individual templates with sample data.
	http.HandleFunc("/preview/verification", func(w http.ResponseWriter, r *http.Request) {
		html, err := renderer.RenderVerification("Semiloore", "36934")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	})

	http.HandleFunc("/preview/welcome", func(w http.ResponseWriter, r *http.Request) {
		html, err := renderer.RenderWelcome("Semiloore", "https://aegis.dev/dashboard")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	})

	addr := ":9090"
	fmt.Printf("📧 Email preview server running at http://localhost%s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
