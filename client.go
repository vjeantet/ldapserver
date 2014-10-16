package ldapserver

import (
	"bufio"
	"log"
	"net"
	"reflect"
	"time"
)

type client struct {
	Numero    int
	srv       *Server
	rwc       net.Conn
	br        *bufio.Reader
	bw        *bufio.Writer
	chan_out  chan LDAPResponse
	helloType string
	helloHost string
}

func (s *client) errorf(format string, args ...interface{}) {
	log.Printf("Client error: "+format, args...)
}

func (s *client) Addr() net.Addr {
	return s.rwc.RemoteAddr()
}

func (c *client) serve() {
	defer c.rwc.Close()
	if onc := c.srv.OnNewConnection; onc != nil {
		if err := onc(c.rwc); err != nil {
			log.Printf("Erreur OnNewConnection: %s", err)
			return
		}
	}

	// Create the ldap response queue to be writted to client (buffered to 20)
	// buffered to 20 means that If client is slow to handler responses, Server
	// Handlers will stop to send more respones
	c.chan_out = make(chan LDAPResponse, 20)

	done := make(chan bool)

	go func() {
		for {
			if c.chan_out == nil && done == nil {
				break
			}
			select {
			case <-done:
				done = nil
				c.close()
				break
			case msg := <-c.chan_out:
				c.writeLdapResult(msg)
			}

		}
	}()

	for {

		if c.srv.ReadTimeout != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(c.srv.ReadTimeout))
		}

		//Read the ASN1/BER binary message
		message_packet, err := readMessagePacket(c.br)
		if err != nil {
			log.Printf("Erreur readMessagePacket: %s", err)
			return
		}

		//Convert binaryMessage to a ldap RequestMessage
		var ldap_request LDAPRequest
		ldap_request, err = message_packet.getRequestMessage()

		if err != nil {
			log.Printf("Error : %s", err.Error())
			break
		}

		// TODO: Use a implementation to limit runnuning request by client
		// NOTE test
		// And WHILE the limit is reached THEN send a BusyLdapMessage

		log.Printf("<<< %d - %s - hex=%x", c.Numero, reflect.TypeOf(ldap_request).Name(), message_packet.Packet.Bytes())

		if _, ok := ldap_request.(UnbindRequest); ok {
			done <- true
			break
		} else {
			go c.ProcessRequestMessage(ldap_request)
		}

	}
}

func (c *client) close() {
	c.chan_out = nil
	c.rwc.Close()
	log.Printf("Connection client [%d] closed", c.Numero)
}

func (c *client) writeLdapResult(lr LDAPResponse) {
	//TODO: encodingToAsn1 should not be reponsability of LDAPResponse, maybe messagepacket
	data := lr.encodeToAsn1()
	log.Printf(">>> %d - %s - hex=%x", c.Numero, reflect.TypeOf(lr).Name(), data)
	c.bw.Write(data)
	c.bw.Flush()
}

func (c *client) ProcessRequestMessage(ldap_request LDAPRequest) {

	switch v := ldap_request.(type) {
	case BindRequest:
		var req = ldap_request.(BindRequest)
		req.out = c.chan_out
		var res = BindResponse{Request: &req}
		c.srv.BindHandler(res, &req)

		if req.wroteMessage == 0 {
			res.ResultCode = LDAPResultSuccess
			c.chan_out <- res
			req.wroteMessage += 1
		}

	case SearchRequest:
		var req SearchRequest = ldap_request.(SearchRequest)
		req.out = c.chan_out
		var r = SearchResponse{Request: &req}
		c.srv.SearchHandler(r, &req)

		if req.searchResultDoneSent == false {
			r.ResultCode = LDAPResultSuccess
			c.chan_out <- r
			req.wroteMessage += 1
		}

	case UnbindRequest:
		log.Fatal("Unbind Request sould not be handled here")

	default:
		log.Fatalf("unexpected type %T", v)
	}
}
