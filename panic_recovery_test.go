package ldapserver

import (
	"net"
	"strings"
	"testing"
	"time"

	gldap "github.com/go-ldap/ldap/v3"
)

type panicReport struct {
	addr      string
	recovered any
	stackLen  int
}

func startPanicTestServer(t *testing.T, onPanic PanicHandler) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := NewServer()
	server.OnPanic = onPanic

	routes := NewRouteMux()
	routes.Bind(func(w ResponseWriter, m *Message) {
		r := m.GetBindRequest()
		if strings.Contains(string(r.Name()), "boom") {
			panic("boom handler panic")
		}
		w.Write(NewBindResponse(LDAPResultSuccess))
	})

	server.Handle(routes)
	server.Listener = ln

	serveDone := make(chan struct{})
	go func() {
		_ = server.serve()
		close(serveDone)
	}()

	stop := func() {
		time.Sleep(200 * time.Millisecond)
		server.Stop()
		<-serveDone
	}

	return ln.Addr().String(), stop
}

func TestHandlerPanicDropsOnlyItsConnection(t *testing.T) {
	reports := make(chan panicReport, 1)
	addr, stop := startPanicTestServer(t, func(conn net.Conn, recovered any, stack []byte) {
		peer := "unknown"
		if conn != nil && conn.RemoteAddr() != nil {
			peer = conn.RemoteAddr().String()
		}
		select {
		case reports <- panicReport{addr: peer, recovered: recovered, stackLen: len(stack)}:
		default:
		}
	})
	defer stop()

	// The panicking client: its connection goes down with the panic.
	evil, err := gldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial evil: %v", err)
	}
	_ = evil.Bind("cn=boom", "secret")
	_ = evil.Close()

	select {
	case rep := <-reports:
		if !strings.HasPrefix(rep.addr, "127.0.0.1:") {
			t.Errorf("OnPanic addr = %q, want 127.0.0.1 client", rep.addr)
		}
		if rep.recovered != "boom handler panic" {
			t.Errorf("OnPanic recovered = %v, want handler value", rep.recovered)
		}
		if rep.stackLen == 0 {
			t.Error("OnPanic stack is empty")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnPanic hook never fired for the panicking connection")
	}

	// Everyone else is unaffected.
	good, err := gldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial good: %v", err)
	}
	defer good.Close()
	if err := good.Bind("cn=ok", "secret"); err != nil {
		t.Fatalf("bind after panic = %v, want success", err)
	}
}
