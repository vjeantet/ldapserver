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
	chDone       chan bool // Channel Done, value => shutdown

	// OnNewConnection, if non-nil, is called on new connections.
	// If it returns non-nil, the connection is closed.
	OnNewConnection func(c net.Conn) error

	// BindHandler called on bind request
	BindHandler func(BindResponse, *BindRequest)

	// SearchHandler called on search request
	SearchHandler func(SearchResponse, *SearchRequest)

	// AddHandler called on add request
	AddHandler func(AddResponse, *AddRequest)

	// DeleteHandler called on delete request
	DeleteHandler func(DeleteResponse, *DeleteRequest)

	// ModifyHandler called on delete request
	ModifyHandler func(ModifyResponse, *ModifyRequest)

	// ExtendedHandler called on delete request
	ExtendedHandler func(ExtendedResponse, *ExtendedRequest)
}

func (s *Server) SetModifyHandler(fn func(ModifyResponse, *ModifyRequest)) {
	s.ModifyHandler = fn
}

func (s *Server) SetAddHandler(fn func(AddResponse, *AddRequest)) {
	s.AddHandler = fn
}

func (s *Server) SetDeleteHandler(fn func(DeleteResponse, *DeleteRequest)) {
	s.DeleteHandler = fn
}

func (s *Server) SetBindHandler(fn func(BindResponse, *BindRequest)) {
	s.BindHandler = fn
}

func (s *Server) SetExtendedHandler(fn func(ExtendedResponse, *ExtendedRequest)) {
	s.ExtendedHandler = fn
}

// SetSearchHandler handle Search's operations used to request a server to return, subject
// to access controls and other restrictions, a set of entries matching
// a complex search criterion.  This can be used to read attributes from
// a single entry, from entries immediately subordinate to a particular
// entry, or from a whole subtree of entries.
// Use the SearchResponse to send all SearchResultEntry
// The fn func should take care of timeLimit and sizeLimit and send the adequats Ldap Response
// LDAPResultTimeLimitExceeded, LDAPResultSizeLimitExceeded, ....
// The fn func should set the result code to send back to the client, if eerything is ok, a resultCode set
// to LDAPResultSuccess
// Listen to *SearchRequest.GetDoneChannel() channel, when a value comes out of this
// channel it means that responses may consumed by the client, because of a AbandonRequest,
// a Server stop, etc....
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

// Termination of the LDAP session is initiated by the server sending a
// Notice of Disconnection.  In this case, each
// protocol peer gracefully terminates the LDAP session by ceasing
// exchanges at the LDAP message layer, tearing down any SASL layer,
// tearing down any TLS layer, and closing the transport connection.
// A protocol peer may determine that the continuation of any
// communication would be pernicious, and in this case, it may abruptly
// terminate the session by ceasing communication and closing the
// transport connection.
// In either case, when the LDAP session is terminated.
// TODO: Send a Disconnection notification
func (s *Server) Stop() {
	close(s.chDone)
	log.Print("waiting for clients shutdown...")
	s.wg.Wait()
	log.Print("all client connections closed")
}

// Handle requests messages on the ln listener
func (s *Server) serve(ln *net.TCPListener) error {
	defer ln.Close()

	// When no BindHandler is set, use the default one to return OK to all
	// BinRequest
	if s.BindHandler == nil {
		s.BindHandler = handleBindRequest
	}

	// When no SearchHandler is set, use the default one to return no entries
	// and a Success response code
	if s.SearchHandler == nil {
		s.SearchHandler = handleSearchRequest
	}

	// When no AddHandler is set, use the default one to return an OperationError
	if s.AddHandler == nil {
		s.AddHandler = handleAddRequest
	}

	// When no ModifyHandler is set, use the default one to return an OperationError
	if s.ModifyHandler == nil {
		s.ModifyHandler = handleModifyRequest
	}

	// When no DeleteHandler is set, use the default one to return an OperationError
	if s.DeleteHandler == nil {
		s.DeleteHandler = handleDeleteRequest
	}

	// When no ExtendedHandler is set, use the default one to return an OperationError
	if s.ExtendedHandler == nil {
		s.ExtendedHandler = handleExtendedRequest
	}

	s.chDone = make(chan bool)
	i := 0
	for {
		select {
		case <-s.chDone:
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
