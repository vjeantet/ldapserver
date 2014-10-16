package ldapserver

import (
	"bufio"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Server is an LDAP server.
type Server struct {
	Addr         string        // TCP address to listen on, ":25" if empty
	Hostname     string        // optional Hostname to announce; "" to use system hostname
	ReadTimeout  time.Duration // optional read timeout
	WriteTimeout time.Duration // optional write timeout

	// OnNewConnection, if non-nil, is called on new connections.
	// If it returns non-nil, the connection is closed.
	OnNewConnection func(c net.Conn) error

	// bindHandler called on bind request
	BindHandler func(BindResponse, *BindRequest)

	// SearchHandler called on search request
	SearchHandler func(SearchResponse, *SearchRequest)

	// UnbindRequestHandler called on unbind request
	UnbindHandler func(*UnbindRequest)
}

func (s *Server) SetBindHandler(fn func(BindResponse, *BindRequest)) {
	s.BindHandler = fn
}

func (s *Server) SetUnbindHandler(fn func(*UnbindRequest)) {
	s.UnbindHandler = fn
}

func (s *Server) SetSearchHandler(fn func(SearchResponse, *SearchRequest)) {
	s.SearchHandler = fn
}

// Returns the server's hostname
// using the hostname command
func (srv *Server) hostname() string {
	if srv.Hostname != "" {
		return srv.Hostname
	}
	out, err := exec.Command("hostname").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ListenAndServe listens on the TCP network address srv.Addr and then
// calls Serve to handle requests on incoming connections.  If
// srv.Addr is blank, ":389" is used.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":389"
	}
	ln, e := net.Listen("tcp", addr)
	if e != nil {
		return e
	}

	log.Printf("Listening on %s%s", srv.hostname(), addr)
	return srv.Serve(ln)
}

// Handle requests messages on the ln listener
func (srv *Server) Serve(ln net.Listener) error {
	defer ln.Close()
	i := 0
	for {
		rw, e := ln.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				log.Printf("ldapd: Accept error: %v", e)
				continue
			}
			return e
		}
		cli, err := srv.newClient(rw)
		if err != nil {
			continue
		}
		i = i + 1
		cli.Numero = i
		log.Printf("Connection client [%d] from %s accepted", cli.Numero, cli.rwc.RemoteAddr().String())
		go cli.serve()
	}
	panic("not reached")
}

// Return a new session with the connection
// client has a writer and reader buffer
func (srv *Server) newClient(rwc net.Conn) (s *client, err error) {
	s = &client{
		srv: srv,
		rwc: rwc,
		br:  bufio.NewReader(rwc),
		bw:  bufio.NewWriter(rwc),
	}
	return
}
