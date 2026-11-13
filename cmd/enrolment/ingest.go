package main

import (
	"bufio"
	"errors"
	"net"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/journal"
)

const (
	maxIngestConns = 4        // front keeps one connection; a few spare for its reloads and restarts
	maxIngestLine  = 64 << 10 // longer lines are dropped
)

// serveIngest takes front's access log (Caddy's `output net`, one JSON line per request) on l and writes
// each line to jw as a front entry, so the journal's daily files and LOG_KEEP apply to it. It returns when
// l is closed. Only the compose network reaches l: the port is never published nor routed by front.
func serveIngest(l net.Listener, jw *journal.Writer) {
	slots := make(chan struct{}, maxIngestConns)
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil { // e.g. out of file descriptors: try again shortly
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				ingest(c, jw)
			}()
		default:
			c.Close()
		}
	}
}

// ingest reads one connection; unparsable and over-long lines are dropped, Write never blocks. No idle
// deadline: front may stay quiet for hours, and the listener's TCP keepalive (Go's default) ends a dead peer.
func ingest(c net.Conn, jw *journal.Writer) {
	defer c.Close()
	r := bufio.NewReaderSize(c, maxIngestLine)
	for {
		line, err := r.ReadSlice('\n')
		for errors.Is(err, bufio.ErrBufferFull) { // too long: skip to its end
			_, err = r.ReadSlice('\n')
			line = nil
		}
		if err != nil {
			return // closed, idle, or a last line without its newline
		}
		if e, ok := journal.ParseCaddy(line); ok {
			jw.Write(e)
		}
	}
}
