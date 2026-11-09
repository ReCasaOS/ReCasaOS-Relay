package proxyproto

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
)

func TestWriteV2Matches(t *testing.T) {
	var b bytes.Buffer
	src := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 51000}
	dst := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 443}
	if err := WriteV2(&b, src, dst); err != nil {
		t.Fatal(err)
	}
	want := []byte("\r\n\r\n\x00\r\nQUIT\n")
	want = append(want, 0x21, 0x11, 0x00, 0x0c, 192, 0, 2, 1, 198, 51, 100, 2, 0xc7, 0x38, 0x01, 0xbb)
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("got % x\nwant % x", b.Bytes(), want)
	}

	b.Reset()
	src6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}
	dst6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 2}
	if err := WriteV2(&b, src6, dst6); err != nil {
		t.Fatal(err)
	}
	if g := b.Bytes(); len(g) != 16+36 || g[13] != 0x21 || g[14] != 0 || g[15] != 36 {
		t.Fatalf("v6 header % x", g[:16])
	}
}

func TestReadV2RoundTrip(t *testing.T) {
	for _, pair := range [][2]*net.TCPAddr{
		{{IP: net.IPv4(192, 0, 2, 1).To4(), Port: 51000}, {IP: net.IPv4(198, 51, 100, 2).To4(), Port: 443}},
		{{IP: net.ParseIP("2001:db8::1"), Port: 1}, {IP: net.ParseIP("2001:db8::2"), Port: 2}},
	} {
		var b bytes.Buffer
		if err := WriteV2(&b, pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
		b.WriteString("payload")
		src, dst, rest, err := ReadProxyV2(&b)
		if err != nil {
			t.Fatal(err)
		}
		if src.String() != pair[0].String() || dst.String() != pair[1].String() {
			t.Fatalf("read %v -> %v, want %v -> %v", src, dst, pair[0], pair[1])
		}
		if p, _ := io.ReadAll(rest); string(p) != "payload" {
			t.Fatalf("rest = %q", p)
		}
	}
	if _, _, _, err := ReadProxyV2(strings.NewReader("GET / HTTP/1.1\r\n\r\n")); err == nil {
		t.Fatal("a non-PROXY stream was accepted")
	}
}
