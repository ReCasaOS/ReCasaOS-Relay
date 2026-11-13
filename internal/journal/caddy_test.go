package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// caddyBlocks splits a Caddyfile into its top-level blocks, which open at column 0 ("{" alone is the global
// options, skipped) and close with "}" at column 0: the (journal) snippet's body, and for each site whether
// it imports the snippet directly.
func caddyBlocks(t *testing.T, text string) (snippet string, sites map[string]bool) {
	t.Helper()
	sites = map[string]bool{}
	var head string
	var body []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		switch {
		case head == "" && strings.HasSuffix(line, " {") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "#"):
			head, body = strings.TrimSuffix(line, " {"), nil
		case head != "" && line == "}":
			if head == "(journal)" {
				snippet = strings.Join(body, "\n")
			} else if !strings.HasPrefix(head, "(") {
				sites[head] = strings.Contains("\n"+strings.Join(body, "\n")+"\n", "\n\timport journal\n")
			}
			head = ""
		case head != "":
			body = append(body, line)
		}
	}
	if len(sites) == 0 {
		t.Fatal("no site block found")
	}
	return snippet, sites
}

func readRepo(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The Caddy that faces the clients (the shipped Caddyfile, or the docs' Caddyfile.tls that replaces it) sends
// its access log to enrolment as JSON lines without headers (Authorization, cookies, X-Box-Signature);
// enrolment keeps them in its journal, so its daily files and LOG_KEEP apply. The e2e TLS layer in front of
// `front` logs nothing, or each request would be logged twice.
func TestShippedCaddyfileLogsJSONWithoutHeaders(t *testing.T) {
	docs := readRepo(t, filepath.Join("docs", "self-hosting.md"))
	start := strings.Index(docs, "<!-- file: Caddyfile.tls -->")
	if start < 0 {
		t.Fatal("docs: no Caddyfile.tls block")
	}
	docs = docs[start:]
	docs = docs[strings.Index(docs, "```")+3:]
	docs = docs[:strings.Index(docs, "```")]

	for name, text := range map[string]string{"Caddyfile": readRepo(t, "Caddyfile"), "docs Caddyfile.tls": docs} {
		snippet, sites := caddyBlocks(t, text)
		for site, imports := range sites {
			if !imports {
				t.Errorf("%s: site %q does not import (journal)", name, site)
			}
		}
		for _, want := range []string{"output net tcp/enrolment:8083", "soft_start", "request>headers delete", "resp_headers delete", "wrap json"} {
			if !strings.Contains(snippet, want) {
				t.Errorf("%s: (journal) snippet lacks %q", name, want)
			}
		}
	}

	tls := readRepo(t, filepath.Join("e2e", "Caddyfile.tls"))
	if _, sites := caddyBlocks(t, tls); strings.Contains(tls, "import journal") || strings.Contains(tls, "\tlog") {
		t.Errorf("e2e/Caddyfile.tls must not log (front behind it does): sites %v", sites)
	}
}
