package ldapserver

import (
	"fmt"
	"reflect"

	roox "github.com/vjeantet/goldap/message"
)

// response is the interface implemented by each ldap response (BinResponse, SearchResponse, SearchEntryResult,...) struct
type response interface {
	SetMessageID(ID int)
}

// ldapResult is the construct used in LDAP protocol to return
// success or failure indications from servers to clients.  To various
// requests, servers will return responses containing the elements found
// in LDAPResult to indicate the final status of the protocol operation
// request.
type ldapResult struct {
	ResultCode        int
	MatchedDN         LDAPDN
	DiagnosticMessage string
	referral          interface{}
	MessageID         int
}

func (e *ldapResult) SetMessageID(ID int) {
	e.MessageID = ID
}

func NewResponse(resultCode int) *ldapResult {
	r := &ldapResult{}
	r.ResultCode = resultCode
	return r
}

type ProtocolOp interface {
}

type Message struct {
	roox.LDAPMessage
	Client *client
	// MessageID  int
	// protocolOp ProtocolOp
	// Controls   Controls
	Done chan bool
}

func (m *Message) String() string {
	return fmt.Sprintf("MessageId=%d, %s", m.MessageID(), reflect.TypeOf(m.ProtocolOp()).Name)
}

// Abandon close the Done channel, to notify handler's user function to stop any
// running process
func (m *Message) Abandon() {
	m.Done <- true
}

//GetDoneChannel return a channel, which indicate the the request should be
//aborted quickly, because the client abandonned the request, the server qui quitting, ...
func (m *Message) GetDoneChannel() chan bool {
	return m.Done
}

func (m *Message) GetAbandonRequest() roox.AbandonRequest {
	return m.ProtocolOp().(roox.AbandonRequest)
}
func (m *Message) GetSearchRequest() roox.SearchRequest {
	return m.ProtocolOp().(roox.SearchRequest)
}

// TODO: switch Authentification type to know if it's a sasl credential or a simple one
func (m *Message) GetBindRequest() roox.BindRequest {
	return m.ProtocolOp().(roox.BindRequest)
}

func (m *Message) GetAddRequest() roox.AddRequest {
	return m.ProtocolOp().(roox.AddRequest)
}

func (m *Message) GetDeleteRequest() roox.DelRequest {
	return m.ProtocolOp().(roox.DelRequest)
}

func (m *Message) GetModifyRequest() roox.ModifyRequest {
	return m.ProtocolOp().(roox.ModifyRequest)
}

func (m *Message) GetCompareRequest() roox.CompareRequest {
	return m.ProtocolOp().(roox.CompareRequest)
}

func (m *Message) GetExtendedRequest() roox.ExtendedRequest {
	return m.ProtocolOp().(roox.ExtendedRequest)
}
