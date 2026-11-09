package sni

import (
	"io"
	"net"
)

// Forward copies a to b and b to a until both directions end, and returns the bytes moved each way.
// When a direction ends it half-closes the destination with CloseWrite, or closes it if it cannot.
// The caller closes both conns afterwards.
func Forward(a, b net.Conn) (aToB, bToA int64) {
	done := make(chan int64)
	cp := func(dst, src net.Conn) int64 {
		n, _ := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		return n
	}
	go func() { done <- cp(b, a) }()
	bToA = cp(a, b)
	return <-done, bToA
}
