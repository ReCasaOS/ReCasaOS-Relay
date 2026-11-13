// Package journaltest gives tests a journal writer over a temp dir and a way to read back what it wrote.
package journaltest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/journal"
)

// New opens a writer for svc; read closes it (flushing) and returns every entry written.
func New(t *testing.T, svc string) (w *journal.Writer, read func() []journal.Entry) {
	t.Helper()
	dir := t.TempDir()
	w, err := journal.Open(dir, svc, time.Hour, 1<<20, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w, func() []journal.Entry {
		w.Close()
		files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		var out []journal.Entry
		for _, f := range files {
			b, _ := os.ReadFile(f)
			dec := json.NewDecoder(bytes.NewReader(b))
			for {
				var e journal.Entry
				if dec.Decode(&e) != nil {
					break
				}
				out = append(out, e)
			}
		}
		return out
	}
}
