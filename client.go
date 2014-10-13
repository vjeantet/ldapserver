package ldap

import (
	"bufio"
	"log"
	"net"
	"reflect"
	"time"

	"github.com/vjeantet/asn1-ber"
)

type client struct {
	Numero    int
	srv       *Server
	rwc       net.Conn
	br        *bufio.Reader
	bw        *bufio.Writer
	chan_out  chan Message
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

	c.chan_out = make(chan Message, 20)

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

		log.Printf("input hex=%x", message_packet.Packet.Bytes())

		//Convert binaryMessage to a ldap RequestMessage
		var ldap_request LDAPRequest
		ldap_request, err = message_packet.getRequestMessage()

		if err != nil {
			log.Printf("Error : %s", err.Error())
			break
		}

		//@Todo When the ldap_request can not be buffered, send a BusyLdapMessage
		log.Printf(">>>>>>>>>>>>>> [%d] %s", c.Numero, reflect.TypeOf(ldap_request).Name())

		if _, ok := ldap_request.(UnbindRequest); ok {
			log.Printf("Connection client [%d] closed", c.Numero)
			c.rwc.Close()
			break
		}
		go c.ProcessRequestMessage(ldap_request)
	}
}

func (c *client) write(data []byte) {
	log.Printf("write hex=%x", data)
	c.bw.Write(data)
	c.bw.Flush()
}

func (c *client) writeLdapResult(lr LDAPResponse) {
	data := lr.encodeToAsn1()
	log.Printf("write hex=%x", data)
	c.bw.Write(data)
	c.bw.Flush()
}

func (c *client) ProcessRequestMessage(ldap_request LDAPRequest) {

	switch v := ldap_request.(type) {
	case BindRequest:
		var req = ldap_request.(BindRequest)
		req.SetClient(c)
		var res = BindResponse{Request: &req}
		c.srv.BindHandler(res, &req)

		if req.wroteMessage == 0 {
			res.ResultCode = LDAPResultSuccess
			c.writeLdapResult(res)
			req.wroteMessage += 1
		}

	case SearchRequest:
		var r = SearchResponse{}
		r.chan_out = c.chan_out

		var req SearchRequest = ldap_request.(SearchRequest)
		c.srv.OnSearchRequest(&r, &req)
		//c.ProcessSearchResponseMessage(*rm, *err)

	case UnbindRequest:
		var req UnbindRequest = ldap_request.(UnbindRequest)
		c.srv.UnbindHandler(&req)
		c.rwc.Close()

	default:
		log.Fatalf("unexpected type %T", v)
	}
}

func (s *client) ProcessUnbindResponseMessage(r Message) {
	s.rwc.Close()
	log.Printf("Connection from %s closed", s.rwc.RemoteAddr().String())
	return
}

func (s *client) ProcessSearchResponseMessage(rm Message, err Error) {
	r := rm.ProtocolOp.(SearchResponse)
	/*
	   Target model
	   - test err
	   - Define ResponseMessages as needed
	   - pass to the s.chan_out channel
	*/

	if err.ResultCode == LDAPResultSuccess {
		for i := range r.Entries {
			packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
			packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(rm.MessageId), "MessageID"))

			searchResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "SearchResultEntry")
			searchResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, r.Entries[i].DN, "LDAPDN"))
			attributes_list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes List")

			for j := range r.Entries[i].Attributes {
				attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
				attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, r.Entries[i].Attributes[j].Name, "type"))
				values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
				for k := range r.Entries[i].Attributes[j].Values {
					values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, r.Entries[i].Attributes[j].Values[k], "val"))
				}
				attributes.AppendChild(values)
				attributes_list.AppendChild(attributes)

			}

			searchResponse.AppendChild(attributes_list)

			packet.AppendChild(searchResponse)
			s.write(packet.Bytes())
		}

		packet2 := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet2.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(rm.MessageId), "MessageID"))

		searchResultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultDone, nil, "Search done")
		searchResultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(LDAPResultSuccess), "ResultCode"))
		searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, "", "MatchedDN"))
		searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, "", "Message"))

		packet2.AppendChild(searchResultDone)

		log.Printf("searchResultDone response hex=%x", packet2.Bytes())

		/*
			Target Model
			Encode the ResponseMessage to Packet
			Write the packet to the buffer out
		*/
		log.Printf("<<<<<<<<<<<<<< [%d] %s", s.Numero, reflect.TypeOf(rm.ProtocolOp).Name())

		s.write(packet2.Bytes())

	} else {
		packet2 := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet2.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(rm.MessageId), "MessageID"))

		searchResultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultDone, nil, "Search done")
		searchResultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(LDAPResultOperationsError), "ResultCode"))
		searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, "", "MatchedDN"))
		searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, "", "Message"))

		packet2.AppendChild(searchResultDone)

		log.Printf("searchResultDone response hex=%x", packet2.Bytes())

		s.write(packet2.Bytes())

	}
}

func (c *client) ProcessBindResponseMessage(br BindResponse) {

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(br.Request.GetMessageId()), "MessageID"))

	bindResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(LDAPResultInvalidCredentials), "ResultCode"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, br.MatchedDN, "MatchedDN"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, br.DiagnosticMessage, "DiagnosticMessage"))

	packet.AppendChild(bindResponse)
	/*
		Target Model
		Encode the Message to Packet
		Write the packet to the buffer out
	*/
	log.Printf("<<<<<<<<<<<<<< [%d] %s", c.Numero, reflect.TypeOf(br).Name())

	c.write(packet.Bytes())
}
