package ldapserver

import "fmt"

// request is the interface implemented by each ldap request (BinRequest, SearchRequest, ...) struct
type request interface {
	getMessageID() int
	String() string
	getProtocolOp() protocolOp
	abort()
}

// response is the interface implemented by each ldap response (BinResponse, SearchResponse, SearchEntryResult,...) struct
type response interface {
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
}

type protocolOp interface {
	String() string
}

type message struct {
	wroteMessage int
	messageID    int
	protocolOp   protocolOp
	Controls     []interface{}
	out          chan response
	Done         chan bool
}

func (m message) getMessageID() int {
	return m.messageID
}

func (m message) String() string {
	return fmt.Sprintf("MessageId=%d, %s", m.messageID, m.protocolOp.String())
}

func (m message) getProtocolOp() protocolOp {
	return m.protocolOp
}

// abort close the Done channel, to notify handler's user function to stop any
// running process
func (m message) abort() {
	close(m.Done)
}

//GetDoneChannel return a channel, which indicate the the request should be
//aborted quickly, because the client abandonned the request, the server qui quitting, ...
func (m *message) GetDoneChannel() chan bool {
	return m.Done
}
