package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shipped Caddy configs write the access log the reader expects (JSON, uncompressed rolls) and never
// write headers (Authorization, cookies, X-Box-Signature).
func TestShippedCaddyfileLogsJSONWithoutHeaders(t *testing.T) {
	for _, name := range []string{"Caddyfile", filepath.Join("e2e", "Caddyfile.tls")} {
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		// Top-level blocks open at column 0 ("{" alone is the global options) and close with "}" at column 0.
		var head, snippet string
		var body []string
		sites := 0
		for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
			switch {
			case head == "" && strings.HasSuffix(line, " {") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "#"):
				head, body = strings.TrimSuffix(line, " {"), nil
			case head != "" && line == "}":
				if head == "(journal)" {
					snippet = strings.Join(body, "\n")
				} else if !strings.HasPrefix(head, "(") {
					sites++
					if !strings.Contains("\n"+strings.Join(body, "\n")+"\n", "\n\timport journal\n") {
						t.Errorf("%s: site %q does not import (journal)", name, head)
					}
				}
				head = ""
			case head != "":
				body = append(body, line)
			}
		}
		if sites == 0 {
			t.Errorf("%s: no site block found", name)
		}
		for _, want := range []string{"output file /logs/front.log", "roll_uncompressed", "request>headers delete", "resp_headers delete", "wrap json"} {
			if !strings.Contains(snippet, want) {
				t.Errorf("%s: (journal) snippet lacks %q", name, want)
			}
		}
	}
}
