package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/auth"
	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// Path is the route a box dials.
const Path = "/v1/share/tunnel"

// ErrNotFound: enrolment does not know the key, or the box has no name. Any other resolve error is a
// transport failure.
var ErrNotFound = errors.New("tunnel: box not found")

// Box is what enrolment knows of a box key.
type Box struct{ Name, NodeID, FleetID string }

// Resolver looks up a box key (the X-Box-Key spelling) at enrolment.
type Resolver func(ctx context.Context, key string) (Box, error)

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard // its errors are the session closing, which the callers already see
	return c
}

// Handler serves GET Path: it verifies the box signature, resolves the key, upgrades to a WebSocket and
// registers the tunnel until the box goes away. Failures before the upgrade are plain HTTP statuses
// (401, 403, 503): the contract's 4401/4403 close codes only exist once the WebSocket is up.
func Handler(reg *Registry, resolve Resolver, now func() time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pub, err := auth.VerifyBox(r, now())
		if err != nil {
			httpError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		key := base64.RawURLEncoding.EncodeToString(pub)
		box, err := resolve(r.Context(), key)
		if errors.Is(err, ErrNotFound) {
			httpError(w, http.StatusForbidden, "box not shared")
			return
		}
		if err != nil {
			log.Printf("tunnel: resolve: %v", err)
			httpError(w, http.StatusServiceUnavailable, "enrolment unavailable")
			return
		}

		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true}) // boxes are not browsers
		if err != nil {
			return
		}
		// The relay opens the streams, so it is the yamux client.
		sess, err := yamux.Client(websocket.NetConn(context.Background(), ws, websocket.MessageBinary), yamuxConfig())
		if err != nil {
			ws.CloseNow()
			return
		}
		t := &Tunnel{Name: box.Name, NodeID: box.NodeID, FleetID: box.FleetID, Key: key, ws: ws, sess: sess}
		if old := reg.Put(box.Name, t); old != nil {
			old.Close(StatusReplaced, "replaced")
		}
		log.Printf("tunnel: %q up", box.Name)
		<-sess.CloseChan()
		reg.Remove(box.Name, t)
		ws.CloseNow()
		log.Printf("tunnel: %q down", box.Name)
	})
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
