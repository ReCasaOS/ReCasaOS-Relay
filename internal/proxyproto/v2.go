// Package proxyproto writes and reads PROXY protocol v2 headers.
package proxyproto

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

var sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// WriteV2 writes a PROXY-command header for a TCP connection from src to dst, IPv4 or IPv6 by src's family.
func WriteV2(w io.Writer, src, dst *net.TCPAddr) error {
	s, d, fam := src.IP.To4(), dst.IP.To4(), byte(0x11)
	if s == nil {
		s, d, fam = src.IP.To16(), dst.IP.To16(), 0x21
	}
	if s == nil || d == nil || (fam == 0x11) != (dst.IP.To4() != nil) {
		return errors.New("proxyproto: src and dst must be valid addresses of the same family")
	}
	h := append([]byte(nil), sig...)
	h = append(h, 0x21, fam)
	h = binary.BigEndian.AppendUint16(h, uint16(2*len(s)+4))
	h = append(h, s...)
	h = append(h, d...)
	h = binary.BigEndian.AppendUint16(h, uint16(src.Port))
	h = binary.BigEndian.AppendUint16(h, uint16(dst.Port))
	_, err := w.Write(h)
	return err
}

// ReadProxyV2 reads a PROXY v2 header from r; rest is r, positioned on the first byte after it.
// A LOCAL command or a non-TCP family yields nil addresses.
func ReadProxyV2(r io.Reader) (src, dst *net.TCPAddr, rest io.Reader, err error) {
	h := make([]byte, 16)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, nil, nil, err
	}
	if string(h[:12]) != string(sig) || h[12]>>4 != 2 {
		return nil, nil, nil, errors.New("proxyproto: not a PROXY v2 header")
	}
	body := make([]byte, binary.BigEndian.Uint16(h[14:]))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, nil, err
	}
	n := 0
	switch h[13] {
	case 0x11:
		n = 4
	case 0x21:
		n = 16
	}
	if h[12]&0x0f != 1 || n == 0 {
		return nil, nil, r, nil
	}
	if len(body) < 2*n+4 {
		return nil, nil, nil, errors.New("proxyproto: short address block")
	}
	src = &net.TCPAddr{IP: net.IP(body[:n]), Port: int(binary.BigEndian.Uint16(body[2*n:]))}
	dst = &net.TCPAddr{IP: net.IP(body[n : 2*n]), Port: int(binary.BigEndian.Uint16(body[2*n+2:]))}
	return src, dst, r, nil
}
