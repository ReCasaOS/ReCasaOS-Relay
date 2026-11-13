package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/journal"
)

func caddyLine(ts time.Time, uri string) string {
	return fmt.Sprintf(`{"level":"info","ts":%.3f,"logger":"http.log.access.log0","msg":"handled request",`+
		`"request":{"remote_ip":"172.29.0.10","client_ip":"203.0.113.7","proto":"HTTP/1.1","method":"GET",`+
		`"host":"relay.example.org","uri":%q,"headers":{"Authorization":["Basic czNjcjN0"]}},`+
		`"bytes_read":0,"duration":0.012,"size":120,"status":200,"resp_headers":{"Set-Cookie":["sid=c00kie"]}}`,
		float64(ts.UnixMilli())/1000, uri)
}

// A Caddy access log line sent to the ingest listener lands in the journal as a front entry, without
// headers; garbage and over-long lines are dropped and the connection goes on.
func TestIngestWritesCaddyLinesAsFrontEntries(t *testing.T) {
	dir := t.TempDir()
	jw, err := journal.Open(dir, "front", time.Hour, 0, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go serveIngest(l, jw)

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	long := caddyLine(now, "/"+strings.Repeat("a", maxIngestLine)) // a valid line, too long
	fmt.Fprint(c, caddyLine(now, "/first")+"\nnot json\n"+long+"\n"+caddyLine(now, "/last")+"\n")
	c.Close()

	name := filepath.Join(dir, "front-"+now.UTC().Format("2006-01-02")+".jsonl")
	var got string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if b, _ := os.ReadFile(name); strings.Contains(string(b), "/last") {
			got = string(b)
			break
		}
	}
	jw.Close()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"path":"/first"`) || !strings.Contains(lines[1], `"path":"/last"`) {
		t.Fatalf("journal = %q, want the /first and /last lines only", got)
	}
	for _, want := range []string{`"src":"front"`, `"svc":"front"`, `"ip":"203.0.113.7"`, `"status":200`, `"ms":12`} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("line %s lacks %s", lines[0], want)
		}
	}
	for _, secret := range []string{"czNjcjN0", "c00kie", "headers"} {
		if strings.Contains(got, secret) {
			t.Errorf("journal holds %q: %s", secret, got)
		}
	}
}

// Past maxIngestConns connections, a new one is closed at once.
func TestIngestLimitsConnections(t *testing.T) {
	jw, err := journal.Open(t.TempDir(), "front", time.Hour, 0, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go serveIngest(l, jw)
	for i := 0; i < maxIngestConns; i++ {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("connection %d: read err = %v, want it closed", maxIngestConns+1, err)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
