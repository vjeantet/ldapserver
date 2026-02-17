package ldapserver

import (
	"net"
	"testing"
	"time"
)

// TestStopRefusesNewConnections verifies that after Stop() returns, the
// server no longer accepts new connections (issue #41).
//
// Before the fix, Stop() could return while the listener was still open,
// allowing new connections to be accepted in the window between wg.Wait()
// completing and serve() checking chDone again.
func TestStopRefusesNewConnections(t *testing.T) {
	Logger = DiscardingLogger

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	server := NewServer()
	routes := NewRouteMux()
	routes.Bind(func(w ResponseWriter, m *Message) {
		res := NewBindResponse(LDAPResultSuccess)
		w.Write(res)
	})
	server.Handle(routes)
	server.Listener = ln

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.serve()
	}()

	// Open a client connection so the server has at least one client.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send a bind request so the connection is fully established.
	if _, err := conn.Write(rawBindRequest); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read bind response: %v", err)
	}
	conn.Close()

	// Give the server a moment to process the client disconnect.
	time.Sleep(100 * time.Millisecond)

	// Stop the server — this must block until the listener is closed.
	server.Stop()

	// After Stop() returns, the listener must be closed and the server
	// must not accept any new connection.
	c2, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		c2.Close()
		t.Fatal("server accepted a connection after Stop() returned")
	}

	// serve() must also have returned.
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("serve() did not return after Stop()")
	}
}
