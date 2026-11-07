package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginPagePlaceholder(t *testing.T) {
	e := setup(t, nil)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	ok := get("/register/hskey-authreq-AAAAAAAAAAAAAAAAAAAAAAAA")
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), "<!-- recasaos-device-login -->") ||
		!strings.HasPrefix(ok.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("valid id: %d %q %q", ok.Code, ok.Header().Get("Content-Type"), ok.Body.String())
	}
	if bad := get("/register/hskey-authreq-short"); bad.Code != http.StatusNotFound {
		t.Fatalf("malformed id = %d, want 404", bad.Code)
	}
}
