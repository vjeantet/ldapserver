package ldapserver

import (
	"bufio"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

type HandlerSource interface {
	GetHandler() Handler
}

// Server is an LDAP server.
type Server struct {
	Listener     net.Listener
	ReadTimeout  time.Duration  // optional read timeout
	WriteTimeout time.Duration  // optional write timeout
	wg           sync.WaitGroup // group of goroutines (1 by client)
	chDone       chan bool      // Channel Done, value => shutdown

	// TLSConfig optionally provides a TLS configuration for use by ServeTLS.
	TLSConfig *tls.Config

	// OnNewConnection, if non-nil, is called on new connections.
	// If it returns non-nil, the connection is closed.
	OnNewConnection func(c net.Conn) error

	// Handler handles ldap message received from client
	// it SHOULD "implement" RequestHandler interface
	Handler          Handler
	useHandlerSource bool
	handlerSource    HandlerSource
}

// NewServer return a LDAP Server
func NewServer() *Server {
	return &Server{
		chDone: make(chan bool),
	}
}

// NewServer returns an LDAP Server, with a dedicated handler for each connection
// different to the "Handler", this allows one struct (object) for each connection.
// this is intented to pass information from one handle function to another, for
// example, if Bind() fails, a flag may be set in the source to decline subsequent searches
// (or limit them in scope).
func NewServerWithHandlerSource(hs HandlerSource) *Server {
	return &Server{
		handlerSource:    hs,
		useHandlerSource: true,
		chDone:           make(chan bool),
	}
}

// Handle registers the handler for the server.
// If a handler already exists for pattern, Handle panics
func (s *Server) Handle(h Handler) {
	if s.useHandlerSource {
		panic("LDAP: attempt to register handler and a handlersource")
	}
	if s.Handler != nil {
		panic("LDAP: multiple Handler registrations")
	}
	s.Handler = h
}

// Serve accepts incoming LDAP connections on the given listener.
// The Server takes ownership of the listener and will close it when Stop is called.
func (s *Server) Serve(listener net.Listener) error {
	s.Listener = listener
	return s.serve()
}

// ServeTLS wraps the given listener with TLS using s.TLSConfig
// and accepts incoming LDAP connections.
func (s *Server) ServeTLS(listener net.Listener) error {
	s.Listener = tls.NewListener(listener, s.TLSConfig)
	return s.serve()
}

// ListenAndServe listens on the TCP network address s.Addr and then
// calls Serve to handle requests on incoming connections.  If
// s.Addr is blank, ":389" is used.
func (s *Server) ListenAndServe(addr string, options ...func(*Server)) error {
	if addr == "" {
		addr = ":389"
	}

	var e error
	s.Listener, e = net.Listen("tcp", addr)
	if e != nil {
		return e
	}
	Logger.Printf("Listening on %s\n", addr)

	for _, option := range options {
		option(s)
	}

	return s.serve()
}

// Handle requests messages on the ln listener
func (s *Server) serve() error {
	if s.Handler == nil && !s.useHandlerSource {
		Logger.Panicln("No LDAP Request Handler defined")
	}

	i := 0

	for {
		rw, err := s.Listener.Accept()
		if err != nil {
			select {
			case <-s.chDone:
				Logger.Print("Stopping server")
				return nil
			default:
			}
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			Logger.Println(err)
			return err
		}

		if s.ReadTimeout != 0 {
			rw.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}
		if s.WriteTimeout != 0 {
			rw.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}

		cli, err := s.newClient(rw)
		if err != nil {
			continue
		}

		i = i + 1
		cli.Numero = i
		Logger.Printf("Connection client [%d] from %s accepted", cli.Numero, cli.rwc.RemoteAddr().String())
		s.wg.Add(1)
		go cli.serve()
	}
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
	if s.useHandlerSource {
		c.handler = s.handlerSource.GetHandler()
	}
	return c, nil
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
func (s *Server) Stop() {
	close(s.chDone)
	s.Listener.Close()
	Logger.Print("gracefully closing client connections...")
	s.wg.Wait()
	Logger.Print("all clients connection closed")
}
