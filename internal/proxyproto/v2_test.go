package proxyproto

import (
	"bytes"
	"net"
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
