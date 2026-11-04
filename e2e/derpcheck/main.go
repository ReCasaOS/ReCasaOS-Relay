// Command derpcheck is an e2e probe of the relay's derper, run in a container on the compose network:
//
//	derpcheck <derp url>                     for a fresh, unknown node key, prints "accepted",
//	                                         "refused: <err>" or "unreachable: <err>"
//	derpcheck stun <host:port>               prints "stun ok" or "stun failed: <err>"
//	derpcheck debugclients <base url> <key>  prints derper's raw /debug/clients/ JSON listing
//
// The first two always exit 0: a non-zero exit means the probe itself broke.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/types/key"
)

const timeout = 15 * time.Second

func main() {
	switch {
	case len(os.Args) == 2:
		fmt.Println(admit(os.Args[1]))
	case len(os.Args) == 3 && os.Args[1] == "stun":
		if err := stunPing(os.Args[2]); err != nil {
			fmt.Println("stun failed:", err)
		} else {
			fmt.Println("stun ok")
		}
	case len(os.Args) == 4 && os.Args[1] == "debugclients":
		if err := debugClients(os.Args[2], os.Args[3]); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("usage: derpcheck <derp url> | stun <host:port> | debugclients <base url> <debug key>")
	}
}

// admit connects with a fresh node key and waits for ServerInfo. Connect alone is not enough: the
// handshake ends with the client's key, and derper verifies it afterwards, then either sends
// ServerInfo or closes the connection. A failed Connect never reached derper's verification, and a
// timeout means derper hung or the stream was misread: both are reported apart ("unreachable"),
// never as a refusal.
func admit(derpURL string) string {
	c, err := derphttp.NewClient(key.NewNode(), derpURL, log.Printf, netmon.NewStatic())
	if err != nil {
		return "unreachable: " + err.Error()
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		return "unreachable: " + err.Error()
	}
	if err := serverInfo(ctx, c); errors.Is(err, errTimeout) {
		return "unreachable: " + err.Error() // a refusal closes the connection; silence is not one
	} else if err != nil {
		return "refused: " + err.Error()
	}
	return "accepted"
}

var errTimeout = errors.New("no ServerInfo and no close before the timeout")

func serverInfo(ctx context.Context, c *derphttp.Client) error {
	done := make(chan error, 1)
	go func() {
		for {
			m, err := c.Recv()
			if err != nil {
				done <- err
				return
			}
			if _, ok := m.(derp.ServerInfoMessage); ok {
				done <- nil
				return
			}
		}
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return errTimeout
	}
}

func stunPing(hostport string) error {
	c, err := net.Dial("udp", hostport)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	tx := stun.NewTxID()
	if _, err := c.Write(stun.Request(tx)); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	got, _, err := stun.ParseResponse(buf[:n])
	if err != nil {
		return err
	}
	if got != tx {
		return errors.New("transaction ID mismatch")
	}
	return nil
}

func debugClients(base, debugKey string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	v := url.Values{"all": {"1"}, "format": {"json"}, "limit": {"1000"}, "debugkey": {debugKey}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/debug/clients/?"+v.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if ue := (*url.Error)(nil); errors.As(err, &ue) {
			err = ue.Err // ue.Error() quotes the URL, which holds the key
		}
		return fmt.Errorf("GET /debug/clients/: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /debug/clients/: HTTP %d", resp.StatusCode)
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}
