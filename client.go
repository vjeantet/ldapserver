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
	Numero      int
	srv         *Server
	rwc         net.Conn
	br          *bufio.Reader
	bw          *bufio.Writer
	chanOut     chan response
	wg          sync.WaitGroup
	closing     bool
	requestList map[int]request
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

	// for each message in c.chanOut send it to client
	go func() {
		for msg := range c.chanOut {
			c.writeLdapResult(msg)
		}

	}()

	// Listen for server signal to shutdown
	go func() {
		for {
			select {
			case <-c.srv.chDone: // server signals shutdown process
				var r = &ExtendedResponse{}
				r.ResultCode = LDAPResultUnwillingToPerform
				r.DiagnosticMessage = "server is about to stop"
				r.responseName = NoticeOfDisconnection
				c.chanOut <- *r
				c.rwc.SetReadDeadline(time.Now().Add(time.Second))
				return
				//TODO: return a UnwillingToPerform to the messagePacket request
			default:
				if c.closing == true {
					return
				}
			}
		}
	}()

	c.requestList = make(map[int]request)

	for {

		if c.srv.ReadTimeout != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(c.srv.ReadTimeout))
		}

		//Read client input as a ASN1/BER binary message
		messagePacket, err := readMessagePacket(c.br)
		if err != nil {
			log.Printf("Error readMessagePacket: %s", err)
			return
		}

		// if client is in closing mode, drop message and exit
		if c.closing == true {
			log.Print("one client message dropped !")
			return
		}

		//Convert ASN1 binaryMessage to a ldap RequestMessage
		var request request
		request, err = messagePacket.getRequestMessage()
		if err != nil {
			log.Printf("Error : %s", err.Error())
			return
		}
		log.Printf("<<< %d - %s - hex=%x", c.Numero, reflect.TypeOf(request).Name(), messagePacket.Packet.Bytes())

		// TODO: Use a implementation to limit runnuning request by client
		// solution 1 : when the buffered output channel is full, send a busy
		// solution 2 : when 10 client requests (goroutines) are running, send a busy message
		// And when the limit is reached THEN send a BusyLdapMessage

		// When message is an UnbindRequest, stop serving
		if _, ok := request.(UnbindRequest); ok {
			return
		} else {

			c.wg.Add(1)
			go c.ProcessRequestMessage(request)
		}
	}

}

// close closes client,
// * stop reading from client
// * signals to all currently running request processor to stop
// * wait for all request processor to end
// * close client connection
// * signal to server that client shutdown is ok
func (c *client) close() {
	log.Printf("client %d close()", c.Numero)
	c.closing = true
	// stop reading from client
	c.rwc.SetReadDeadline(time.Now().Add(time.Second))

	// signals to all currently running request processor to stop
	for messageID, request := range c.requestList {
		log.Printf("Client [%d] sent abandon signal to request[messageID = %d]", c.Numero, messageID)
		request.abort()
	}

	// wait for all request processor to end
	//log.Printf("waiting the end of current (%d) client's requests", c.Numero)
	c.wg.Wait()
	close(c.chanOut)
	log.Printf("client [%d] request processors ended", c.Numero)

	// close client connection
	c.rwc.Close()
	log.Printf("client [%d] connection closed", c.Numero)

	// signal to server that client shutdown is ok
	c.srv.wg.Done()
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
	defer delete(c.requestList, request.getMessageID())

	switch v := request.(type) {
	case BindRequest:
		var req = request.(BindRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		c.requestList[request.getMessageID()] = &req
		var res = BindResponse{request: &req}
		c.srv.BindHandler(res, &req)

	case SearchRequest:
		var req = request.(SearchRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		c.requestList[request.getMessageID()] = &req

		var res = SearchResponse{request: &req}
		c.srv.SearchHandler(res, &req)

	case AbandonRequest:
		var req = request.(AbandonRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		messageIDToAbandon := req.getMessageID()
		c.requestList[request.getMessageID()] = &req

		// retreive the request to abandon, and send a abort signal to it
		if requestToAbandon, ok := c.requestList[messageIDToAbandon]; ok {
			requestToAbandon.abort()
			log.Printf("Abandon signal sent to request processor [messageID=%d]", messageIDToAbandon)
		}

	case AddRequest:
		var req = request.(AddRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		c.requestList[request.getMessageID()] = &req

		var res = AddResponse{request: &req}
		c.srv.AddHandler(res, &req)

	case DeleteRequest:
		var req = request.(DeleteRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		c.requestList[request.getMessageID()] = &req

		var res = DeleteResponse{request: &req}
		c.srv.DeleteHandler(res, &req)

	case UnbindRequest:
		log.Print("Unbind Request sould not be handled here")

	default:
		log.Printf("WARNING : unexpected type %v", v)
	}

}
