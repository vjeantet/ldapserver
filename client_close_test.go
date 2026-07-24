package ldapserver

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gldap "github.com/go-ldap/ldap/v3"
)

const testClientCloseData = "bound-session"

func startClientCloseTestServer(t *testing.T, onClose ClientCloseHandler) (*Server, string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := NewServer()
	server.OnClientClose = onClose

	routes := NewRouteMux()
	routes.Bind(func(w ResponseWriter, m *Message) {
		m.Client.SetData(testClientCloseData)
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

	return server, ln.Addr().String(), stop
}

func bindClientForUnbindTest(t *testing.T, addr string) *gldap.Conn {
	t.Helper()

	conn, err := gldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if err := conn.Bind("cn=test", "secret"); err != nil {
		conn.Close()
		t.Fatalf("bind: %v", err)
	}

	return conn
}

func bindClientForAbruptDisconnectTest(t *testing.T, addr string) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if _, err := conn.Write(rawBindRequest); err != nil {
		conn.Close()
		t.Fatalf("write bind request: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		conn.Close()
		t.Fatalf("set read deadline: %v", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		t.Fatalf("read bind response: %v", err)
	}

	if n == 0 {
		conn.Close()
		t.Fatal("empty bind response")
	}

	return conn
}

func waitForCloseHookValue(t *testing.T, ch <-chan any) any {
	t.Helper()

	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for OnClientClose")
		return nil
	}
}

func waitForSignal(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for %s", name)
	}
}

func TestClientCloseHook_UnbindPassesDataAndRunsOnce(t *testing.T) {
	var calls atomic.Int32
	values := make(chan any, 1)

	_, addr, stop := startClientCloseTestServer(t, func(_ net.Conn, data any) {
		if calls.Add(1) == 1 {
			values <- data
		}
	})

	var stopOnce sync.Once
	stopServer := func() {
		stopOnce.Do(stop)
	}
	defer stopServer()

	conn := bindClientForUnbindTest(t, addr)

	if err := conn.Unbind(); err != nil {
		t.Fatalf("unbind: %v", err)
	}

	got := waitForCloseHookValue(t, values)
	if got != testClientCloseData {
		t.Fatalf("unexpected close hook data: got=%v want=%v", got, testClientCloseData)
	}

	time.Sleep(100 * time.Millisecond)

	if got := calls.Load(); got != 1 {
		t.Fatalf("unexpected close hook call count: got=%d want=1", got)
	}
}

func TestClientCloseHook_AbruptDisconnectPassesDataAndRunsOnce(t *testing.T) {
	var calls atomic.Int32
	values := make(chan any, 1)

	_, addr, stop := startClientCloseTestServer(t, func(_ net.Conn, data any) {
		if calls.Add(1) == 1 {
			values <- data
		}
	})

	var stopOnce sync.Once
	stopServer := func() {
		stopOnce.Do(stop)
	}
	defer stopServer()

	conn := bindClientForAbruptDisconnectTest(t, addr)
	conn.Close()

	got := waitForCloseHookValue(t, values)
	if got != testClientCloseData {
		t.Fatalf("unexpected close hook data: got=%v want=%v", got, testClientCloseData)
	}

	time.Sleep(100 * time.Millisecond)

	if got := calls.Load(); got != 1 {
		t.Fatalf("unexpected close hook call count: got=%d want=1", got)
	}
}

func TestClientCloseHook_PanicDoesNotBreakStop(t *testing.T) {
	var calls atomic.Int32
	called := make(chan struct{}, 1)

	_, addr, stop := startClientCloseTestServer(t, func(_ net.Conn, _ any) {
		calls.Add(1)
		select {
		case called <- struct{}{}:
		default:
		}
		panic("boom")
	})

	var stopOnce sync.Once
	stopServer := func() {
		stopOnce.Do(stop)
	}
	defer stopServer()

	conn := bindClientForAbruptDisconnectTest(t, addr)
	conn.Close()

	waitForSignal(t, called, "OnClientClose")

	stopped := make(chan struct{})
	go func() {
		stopServer()
		close(stopped)
	}()

	waitForSignal(t, stopped, "server.Stop")

	if got := calls.Load(); got != 1 {
		t.Fatalf("unexpected close hook call count: got=%d want=1", got)
	}
}
