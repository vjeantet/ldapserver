package ldapserver

import (
	"net"
	"testing"
)

func TestRouteMuxCloseRegistersServerOnClientClose(t *testing.T) {
	server := NewServer()

	var prevCalled bool
	server.OnClientClose = func(_ net.Conn, _ any) {
		prevCalled = true
	}

	var routeCalled bool
	routes := NewRouteMux()
	routes.Close(func(_ net.Conn, _ any) {
		routeCalled = true
	})

	server.Handle(routes)

	if server.OnClientClose == nil {
		t.Fatal("expected OnClientClose to be registered")
	}

	server.OnClientClose(nil, nil)

	if !prevCalled {
		t.Fatal("expected existing OnClientClose to be preserved")
	}

	if !routeCalled {
		t.Fatal("expected RouteMux close handler to be called")
	}
}
