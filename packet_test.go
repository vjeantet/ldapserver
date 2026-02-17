package ldapserver

import (
	"net"
	"testing"
	"time"
)

// listenOnAvailablePort starts an LDAP server with a Bind handler on a random
// available port and returns the server, its address, and a stop function.
// The stop function waits briefly for client goroutines to clean up before
// initiating server shutdown, avoiding a pre-existing race in the shutdown
// goroutine (unrelated to the fixes being tested here).
func listenOnAvailablePort(t *testing.T) (*Server, net.Addr, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := NewServer()
	routes := NewRouteMux()
	routes.Bind(func(w ResponseWriter, m *Message) {
		res := NewBindResponse(LDAPResultSuccess)
		w.Write(res)
	})
	server.Handle(routes)
	server.Listener = ln

	go server.serve()

	return server, ln.Addr(), func() {
		time.Sleep(200 * time.Millisecond)
		server.Stop()
	}
}

// Raw LDAP Simple Bind Request: messageID=1, version=3, name="cn=test", password="secret"
var rawBindRequest = []byte{
	0x30, 0x19, // SEQUENCE (25 bytes)
	0x02, 0x01, 0x01, // INTEGER messageID=1
	0x60, 0x14, // APPLICATION 0 BindRequest (20 bytes)
	0x02, 0x01, 0x03, // INTEGER version=3
	0x04, 0x07, 0x63, 0x6e, 0x3d, 0x74, 0x65, 0x73, 0x74, // OCTET STRING "cn=test"
	0x80, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // CONTEXT 0 simple auth "secret"
}

func TestValidBindRequest(t *testing.T) {
	_, addr, stop := listenOnAvailablePort(t)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(rawBindRequest); err != nil {
		t.Fatalf("write bind request: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if n == 0 {
		t.Fatal("empty response from server")
	}

	resp, err := decodeMessage(buf[:n])
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.ProtocolOpName() != "BindResponse" {
		t.Fatalf("expected BindResponse, got %s", resp.ProtocolOpName())
	}
}

func TestValidBindAfterInvalidConnection(t *testing.T) {
	_, addr, stop := listenOnAvailablePort(t)
	defer stop()

	// First: send invalid bytes (TLS ClientHello tag 0x16).
	bad, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("dial bad: %v", err)
	}
	bad.Write([]byte{0x16, 0x03, 0x01})
	bad.SetReadDeadline(time.Now().Add(time.Second))
	tmp := make([]byte, 128)
	bad.Read(tmp)
	bad.Close()

	time.Sleep(100 * time.Millisecond)

	// Second: a legitimate LDAP Bind on a new connection must work.
	conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("server not accepting connections after invalid packet: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(rawBindRequest); err != nil {
		t.Fatalf("write bind request: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	resp, err := decodeMessage(buf[:n])
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.ProtocolOpName() != "BindResponse" {
		t.Fatalf("expected BindResponse, got %s", resp.ProtocolOpName())
	}
}

func TestInvalidFirstByte_NoServerCrash(t *testing.T) {
	_, addr, stop := listenOnAvailablePort(t)
	defer stop()

	// Send an invalid first byte (0x16 = TLS ClientHello tag, the exact
	// scenario from issue #18).
	conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write([]byte{0x16, 0x03, 0x01})
	buf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	conn.Read(buf)
	conn.Close()

	time.Sleep(100 * time.Millisecond)

	// If we get here without the test process crashing, the panic is fixed.
	conn2, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("server no longer accepting connections after invalid packet: %v", err)
	}
	conn2.Close()
}

func TestGarbageBytes_NoServerCrash(t *testing.T) {
	_, addr, stop := listenOnAvailablePort(t)
	defer stop()

	// Send an HTTP request (first byte 'G' = 0x47, not 0x30).
	conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	buf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	conn.Read(buf)
	conn.Close()

	time.Sleep(100 * time.Millisecond)

	conn2, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("server no longer accepting connections after garbage bytes: %v", err)
	}
	conn2.Close()
}
