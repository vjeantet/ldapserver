package ldapserver

import (
	"bufio"
	"crypto/tls"
	"fmt"
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
		}
		log.Printf("<<< %d - %s - hex=%x", c.Numero, reflect.TypeOf(request).Name(), messagePacket.Packet.Bytes())

		// TODO: Use a implementation to limit runnuning request by client
		// solution 1 : when the buffered output channel is full, send a busy
		// solution 2 : when 10 client requests (goroutines) are running, send a busy message
		// And when the limit is reached THEN send a BusyLdapMessage

		// When message is an UnbindRequest, stop serving
		if _, ok := request.(UnbindRequest); ok {
			return
		}

		// If client requests a startTls, do not handle it in a
		// goroutine, connection has to remain free until TLS is OK
		// @see RFC https://tools.ietf.org/html/rfc4511#section-4.14.1
		if req, ok := request.(ExtendedRequest); ok {
			if req.GetResponseName() == NoticeOfStartTLS {
				c.wg.Add(1)
				c.ProcessRequestMessage(request)
				continue
			}
		}

		// TODO: go/non go routine choice should be done in the ProcessRequestMessage
		// not in the client.serve func
		c.wg.Add(1)
		go c.ProcessRequestMessage(request)
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
	c.closing = true //FIXME: subject to data race condition ?
	// stop reading from client
	c.rwc.SetReadDeadline(time.Now().Add(time.Second))

	// TODO: Send a Disconnection notification

	// signals to all currently running request processor to stop
	for messageID, request := range c.requestList {
		log.Printf("Client [%d] sent abandon signal to request[messageID = %d]", c.Numero, messageID)
		go request.abort()
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
	data := newMessagePacket(lr).Bytes()
	log.Printf(">>> %d - %s - hex=%x", c.Numero, reflect.TypeOf(lr).Name(), data)
	c.bw.Write(data)
	c.bw.Flush()
}

func (c *client) ProcessRequestMessage(request request) {
	defer c.wg.Done()
	defer delete(c.requestList, request.getMessageID())

	switch request.(type) {
	case BindRequest:
		var req = request.(BindRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		c.requestList[request.getMessageID()] = &req
		var res = BindResponse{request: &req}
		c.srv.Handler.bind(res, &req)

	case SearchRequest:
		var req = request.(SearchRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		c.requestList[request.getMessageID()] = &req

		var res = SearchResponse{request: &req}
		c.srv.Handler.search(res, &req)

	case AbandonRequest:
		var req = request.(AbandonRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		messageIDToAbandon := req.getIDToAbandon()
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
		c.srv.Handler.add(res, &req)

	case DeleteRequest:
		var req = request.(DeleteRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		c.requestList[request.getMessageID()] = &req

		var res = DeleteResponse{request: &req}
		c.srv.Handler.delete(res, &req)

	case ModifyRequest:
		var req = request.(ModifyRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		c.requestList[request.getMessageID()] = &req

		var res = ModifyResponse{request: &req}
		c.srv.Handler.modify(res, &req)

	case UnbindRequest:
		log.Print("Unbind Request sould not be handled here")

	case ExtendedRequest:
		var req = request.(ExtendedRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		c.requestList[request.getMessageID()] = &req
		var res = ExtendedResponse{request: &req}
		if req.GetResponseName() == NoticeOfStartTLS {
			tlsConn := tls.Server(c.rwc, c.srv.TLSconfig)
			res.ResultCode = LDAPResultSuccess
			res.responseName = NoticeOfStartTLS
			c.writeLdapResult(res)

			if err := tlsConn.Handshake(); err != nil {
				log.Printf("StartTLS Handshake error %v", err)
				res.DiagnosticMessage = fmt.Sprintf("StartTLS Handshake error : \"%s\"", err.Error())
				res.ResultCode = LDAPResultOperationsError
				c.writeLdapResult(res)
				return
			}

			c.rwc = tlsConn
			c.br = bufio.NewReader(c.rwc)
			c.bw = bufio.NewWriter(c.rwc)
			log.Println("StartTLS OK")
		} else {
			c.srv.Handler.extended(res, &req)
		}

	case CompareRequest:
		var req = request.(CompareRequest)
		req.out = c.chanOut
		req.Done = make(chan bool)
		c.requestList[request.getMessageID()] = &req
		var res = CompareResponse{request: &req}
		c.srv.Handler.compare(res, &req)

	default:
		c.srv.Handler.unknow(&request)
	}

}
