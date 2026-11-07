package server

import (
	"net/http"

	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
)

// loginPage answers Headscale's web-login URL (<server_url>/register/<auth id>), which Caddy routes
// here. Placeholder: it only proves the takeover; the real device-code form replaces it.
func loginPage(w http.ResponseWriter, r *http.Request) {
	if !headscale.ValidAuthID(r.PathValue("authID")) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte("<!doctype html><title>Sign in</title><!-- recasaos-device-login -->\n"))
}
