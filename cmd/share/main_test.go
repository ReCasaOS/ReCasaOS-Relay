package main

import (
	"errors"
	"net"
	"sync"
	"testing"
)

type flakyListener struct {
	net.Listener
	calls int
	conn  net.Conn
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.calls++
	switch l.calls {
	case 1:
		return nil, errors.New("accept: too many open files")
	case 2:
		return l.conn, nil
	}
	return nil, net.ErrClosed
}

func TestAcceptSurvivesTemporaryError(t *testing.T) {
	c, peer := net.Pipe()
	defer peer.Close()
	served := make(chan struct{})
	var wg sync.WaitGroup
	accept(&flakyListener{conn: c}, &wg, func(net.Conn) { close(served) })
	wg.Wait()
	select {
	case <-served:
	default:
		t.Fatal("connection after a temporary Accept error was not served")
	}
}
