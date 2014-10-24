package ldapserver

import (
	"bufio"
	"log"
	"net"
	"reflect"
	"sync"
	"time"
)

type client struct {
	Numero  int
	srv     *Server
	rwc     net.Conn
	br      *bufio.Reader
	bw      *bufio.Writer
	chanOut chan response
	wg      sync.WaitGroup
	closing bool
}

func (c *client) Addr() net.Addr {
	return c.rwc.RemoteAddr()
}

func (c *client) serve() {
	defer c.close()

	if onc := c.srv.OnNewConnection; onc != nil {
		if err := onc(c.rwc); err != nil {
			log.Printf("Erreur OnNewConnection: %s", err)
			return
		}
	}

	// Create the ldap response queue to be writted to client (buffered to 20)
	// buffered to 20 means that If client is slow to handler responses, Server
	// Handlers will stop to send more respones
	c.chanOut = make(chan response)

	go func() {
		defer log.Println("reponses pipeline stopped")

		for msg := range c.chanOut {
			c.writeLdapResult(msg)
		}

	}()

	for {

		select {
		case <-c.srv.ch:
			log.Print("Stopping client")
			//TODO: return a UnwillingToPerform to the messagePacket request
			return
		default:
		}

		if c.srv.ReadTimeout != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(c.srv.ReadTimeout))
		}
		//Read the ASN1/BER binary message
		messagePacket, err := readMessagePacket(c.br)
		if err != nil {
			log.Printf("Erreur readMessagePacket: %s", err)
			c.srv.ch <- true
			return
		}

		//Convert binaryMessage to a ldap RequestMessage
		var request request
		request, err = messagePacket.getRequestMessage()

		if err != nil {
			log.Printf("Error : %s", err.Error())
			return
		}

		// TODO: Use a implementation to limit runnuning request by client
		// NOTE test
		// And WHILE the limit is reached THEN send a BusyLdapMessage

		log.Printf("<<< %d - %s - hex=%x", c.Numero, reflect.TypeOf(request).Name(), messagePacket.Packet.Bytes())

		if _, ok := request.(UnbindRequest); ok {
			return
		}

		c.wg.Add(1)
		go c.ProcessRequestMessage(request)

	}

}

func (c *client) close() {
	c.closing = true
	log.Print("waiting the end of current client's requests")
	c.wg.Wait()
	close(c.chanOut)
	log.Print("client's requests ended")

	c.rwc.Close()

	c.srv.wg.Done()
	log.Printf("Connection client [%d] closed", c.Numero)
}

func (c *client) writeLdapResult(lr response) {
	//TODO: encodingToAsn1 should not be reponsability of Response, maybe messagepacket
	data := lr.encodeToAsn1()
	log.Printf(">>> %d - %s - hex=%x", c.Numero, reflect.TypeOf(lr).Name(), data)
	c.bw.Write(data)
	c.bw.Flush()
}

func (c *client) ProcessRequestMessage(request request) {
	defer c.wg.Done()

	switch v := request.(type) {
	case BindRequest:
		var req = request.(BindRequest)
		req.out = c.chanOut
		req.Done = c.srv.ch
		var res = BindResponse{request: &req}
		if h := c.srv.BindHandler; h != nil {
			h(res, &req)
		} else {
			res.ResultCode = LDAPResultUnwillingToPerform
			res.DiagnosticMessage = "not implemented"
			res.Send()
		}

	case SearchRequest:
		var req = request.(SearchRequest)
		req.out = c.chanOut
		req.Done = c.srv.ch
		var res = SearchResponse{request: &req}
		if h := c.srv.SearchHandler; h != nil {
			h(res, &req)
		} else {
			res.ResultCode = LDAPResultUnwillingToPerform
			res.DiagnosticMessage = "not implemented"
			res.Send()
		}

	case UnbindRequest:
		log.Fatal("Unbind Request sould not be handled here")

	default:
		log.Fatalf("unexpected type %T", v)
	}

}
