package server

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/devicecode"
	"github.com/ReCasaOS/recasaos-relay/internal/fakes"
)

const authID = "hskey-authreq-AAAAAAAAAAAAAAAAAAAAAAAA"

type loginEnv struct {
	env
	log *fakes.Log
	hs  *fakes.HS
	id  string
}

func setupLogin(t *testing.T, mutate func(*Config, *Deps)) loginEnv {
	t.Helper()
	log := &fakes.Log{}
	hs := fakes.NewHS(log, func() time.Time { return now0 })
	var st env
	st = setup(t, func(c *Config, d *Deps) {
		c.LoginRatePerHour = 20
		c.DeviceCodeTTL = 10 * time.Minute
		d.Headscale = hs
		if mutate != nil {
			mutate(c, d)
		}
	})
	addFleet(t, st.st, "fleet0001")
	return loginEnv{st, log, hs, "fleet0001"}
}

// code makes a device code for the fleet, valid at now0.
func (e loginEnv) code(t *testing.T) string {
	t.Helper()
	c, err := devicecode.New()
	if err != nil {
		t.Fatal(err)
	}
	n, _ := devicecode.Normalize(c)
	if err := e.st.CreateDeviceCode(context.Background(), e.id, devicecode.Hash(n), now0.Add(time.Hour), now0, 100); err != nil {
		t.Fatal(err)
	}
	return c
}

func (e loginEnv) get(id, lang string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/register/"+id, nil)
	if lang != "" {
		r.Header.Set("Accept-Language", lang)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func (e loginEnv) post(id, code, lang, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/register/"+id, strings.NewReader(url.Values{"code": {code}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if lang != "" {
		r.Header.Set("Accept-Language", lang)
	}
	r.RemoteAddr = remote
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func (e loginEnv) registers() int {
	n := 0
	for _, c := range e.log.Calls() {
		if strings.HasPrefix(c, "register:") {
			n++
		}
	}
	return n
}

func TestLoginForm(t *testing.T) {
	e := setupLogin(t, nil)
	rec := e.get(authID, "")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, s := range []string{`<form method="post">`, `name="code"`, "<!-- recasaos-device-login -->", "Enter the code",
		"Only enter a code if you just started this login in the Tailscale app on this device."} {
		if !strings.Contains(body, s) {
			t.Fatalf("body lacks %q:\n%s", s, body)
		}
	}
	for k, v := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
	} {
		if got := rec.Header().Get(k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
	if e.get("hskey-authreq-short", "").Code != http.StatusNotFound {
		t.Fatal("invalid id not 404")
	}
	if fr := e.get(authID, "fr-FR,fr;q=0.9").Body.String(); !strings.Contains(fr, "Saisis le code") ||
		!strings.Contains(fr, html.EscapeString("Ne saisis un code que si tu viens de lancer cette connexion dans l'app Tailscale, sur cet appareil.")) {
		t.Fatalf("not French: %s", fr)
	}
}

func TestLoginApproves(t *testing.T) {
	e := setupLogin(t, nil)
	rec := e.post(authID, e.code(t), "", ip1)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Device added: device-1") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got := e.log.Calls(); len(got) != 1 || got[0] != "register:f-fleet0001" {
		t.Fatalf("calls %v", got)
	}
	ids, err := e.st.DeviceIDs(context.Background(), e.id)
	if err != nil || len(ids) != 1 || !ids["1"] {
		t.Fatalf("devices %v %v", ids, err)
	}
	if fr := setupLogin(t, nil); !strings.Contains(fr.post(authID, fr.code(t), "fr", ip1).Body.String(), "Appareil ajouté : device-1") {
		t.Fatal("not French")
	}
}

func TestLoginEscapesHostname(t *testing.T) {
	e := setupLogin(t, nil)
	e.hs.RegisterHostname = "<script>alert(1)</script>"
	body := e.post(authID, e.code(t), "", ip1).Body.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("hostname not escaped:\n%s", body)
	}
}

func TestLoginCodeUsedOnce(t *testing.T) {
	e := setupLogin(t, nil)
	c := e.code(t)
	e.post(authID, c, "", ip1)
	rec := e.post(authID, c, "", ip1)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid or already used") || e.registers() != 1 {
		t.Fatalf("%d registers=%d %s", rec.Code, e.registers(), rec.Body)
	}
	e2 := setupLogin(t, nil)
	if fr := e2.post(authID, "ABCD-EFGH", "fr", ip1); fr.Code != 400 || !strings.Contains(fr.Body.String(), "invalide ou déjà utilisé") {
		t.Fatalf("%d %s", fr.Code, fr.Body)
	}
}

func TestLoginWrongCode(t *testing.T) {
	e := setupLogin(t, nil)
	for _, c := range []string{"ABCD-EFGH", "nonsense", ""} {
		rec := e.post(authID, c, "", ip1)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `name="code"`) {
			t.Fatalf("%q: %d %s", c, rec.Code, rec.Body)
		}
	}
	if e.registers() != 0 {
		t.Fatal("registered")
	}
}

func TestLoginExpiredAuthRequest(t *testing.T) {
	e := setupLogin(t, nil)
	e.hs.Expired = map[string]bool{authID: true}
	rec := e.post(authID, e.code(t), "", ip1)
	if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), "Tailscale app") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if ids, _ := e.st.DeviceIDs(context.Background(), e.id); len(ids) != 0 {
		t.Fatalf("devices %v", ids)
	}
}

func TestLoginHeadscaleDown(t *testing.T) {
	e := setupLogin(t, nil)
	e.hs.Fail("register", context.DeadlineExceeded)
	if rec := e.post(authID, e.code(t), "", ip1); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "Generate a new code") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if fr := e.post(authID, e.code(t), "fr", ip1); !strings.Contains(fr.Body.String(), "Génère un nouveau code") {
		t.Fatalf("%d %s", fr.Code, fr.Body)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := setupLogin(t, nil)
	for i := 0; i < 20; i++ {
		if rec := e.post(authID, "ABCD-EFGH", "", ip1); rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d = %d", i, rec.Code)
		}
	}
	rec := e.post(authID, e.code(t), "", ip1)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" || e.registers() != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if e.post(authID, e.code(t), "", "192.0.2.9:1").Code != http.StatusOK {
		t.Fatal("other IP blocked")
	}
}

// One /48 holds 65,536 /64s: it gets prefix48Factor times the per-/64 rate in all.
func TestLoginRateLimitPer48(t *testing.T) {
	e := setupLogin(t, nil)
	for i := 0; i < 200; i++ { // 200 distinct /64s of 2001:db8:5::/48, one try each
		if rec := e.post(authID, "ABCD-EFGH", "", "[2001:db8:5:"+strconv.FormatInt(int64(i+1), 16)+"::1]:1"); rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d = %d", i, rec.Code)
		}
	}
	if rec := e.post(authID, e.code(t), "", "[2001:db8:5:ffff::1]:1"); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("fresh /64 of the same /48 = %d", rec.Code)
	}
	if rec := e.post(authID, e.code(t), "", "[2001:db8:6:1::1]:1"); rec.Code != http.StatusOK {
		t.Fatalf("another /48 = %d", rec.Code)
	}
	if e.registers() != 1 {
		t.Fatalf("registers %d", e.registers())
	}
}

func TestLoginBodyTooLarge(t *testing.T) {
	e := setupLogin(t, nil)
	r := httptest.NewRequest(http.MethodPost, "/register/"+authID, strings.NewReader("code="+strings.Repeat("A", 2048)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("%d", rec.Code)
	}
}
