package ldapserver

import (
	"bufio"
	"log"
	"net"
	"sync"
	"time"
)

// Server is an LDAP server.
type Server struct {
	Addr         string        // TCP address to listen on, ":389" if empty
	ReadTimeout  time.Duration // optional read timeout
	WriteTimeout time.Duration // optional write timeout
	wg           sync.WaitGroup
	ch           chan bool

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

// ListenAndServe listens on the TCP network address s.Addr and then
// calls Serve to handle requests on incoming connections.  If
// s.Addr is blank, ":389" is used.
func (s *Server) ListenAndServe() error {
	addr := s.Addr
	if addr == "" {
		addr = ":389"
	}

	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if nil != err {
		log.Fatalln(err)
	}

	ln, e := net.ListenTCP("tcp", laddr)
	if e != nil {
		return e
	}

	log.Printf("Listening on %s", addr)
	return s.serve(ln)
}

func (s *Server) Stop() {
	close(s.ch)
	log.Print("waiting for client connections to be closed...")
	s.wg.Wait()
	log.Print("all client connections closed")
}

// Handle requests messages on the ln listener
func (s *Server) serve(ln *net.TCPListener) error {
	defer ln.Close()
	s.ch = make(chan bool)
	i := 0
	for {
		select {
		case <-s.ch:
			log.Print("Stopping server")
			ln.Close()
			return nil
		default:
		}

		ln.SetDeadline(time.Now().Add(1e9))
		rw, err := ln.AcceptTCP()
		if nil != err {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			log.Println(err)
		}
		//rw.SetDeadline(time.Now().Add(1e9))
		cli, err := s.newClient(rw)
		if err != nil {
			continue
		}

		i = i + 1
		cli.Numero = i
		log.Printf("Connection client [%d] from %s accepted", cli.Numero, cli.rwc.RemoteAddr().String())
		s.wg.Add(1)
		go cli.serve()
	}

	return nil
}

// Return a new session with the connection
// client has a writer and reader buffer
func (s *Server) newClient(rwc net.Conn) (c *client, err error) {
	c = &client{
		srv: s,
		rwc: rwc,
		br:  bufio.NewReader(rwc),
		bw:  bufio.NewWriter(rwc),
	}
	return c, nil
}
