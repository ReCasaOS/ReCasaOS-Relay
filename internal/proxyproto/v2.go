// Package proxyproto writes PROXY protocol v2 headers.
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
