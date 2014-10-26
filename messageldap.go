package ldapserver

import "fmt"

type protocolOp interface {
	String() string
}

type request interface {
	getMessageID() int
	String() string
	getProtocolOp() protocolOp
	abort()
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

// a BindRequest struct
type BindRequest struct {
	message
	protocolOp struct {
		Version  int
		Login    []byte
		Password []byte
	}
}

func (r *BindRequest) SetLogin(login []byte) {
	r.protocolOp.Login = login
}

func (r *BindRequest) GetLogin() []byte {
	return r.protocolOp.Login
}

func (r *BindRequest) SetVersion(version int) {
	r.protocolOp.Version = version
}

func (r *BindRequest) SetPassword(password []byte) {
	r.protocolOp.Password = password
}

func (r *BindRequest) GetPassword() []byte {
	return r.protocolOp.Password
}

func (r BindRequest) String() string {
	var s string

	s = fmt.Sprintf("Login:%s, Password:%s",
		r.GetLogin(),
		r.GetPassword())

	return s
}

// UnbindRequest's function is to terminate an LDAP session.
// The Unbind operation is not the antithesis of the Bind operation as
// the name implies.  The naming of these operations are historical.
// The Unbind operation should be thought of as the "quit" operation.
type UnbindRequest struct {
	message
	protocolOp struct {
	}
}

// DeleteRequest is a definition of the Delete Operation
type DeleteRequest struct {
	message
	protocolOp LDAPDN
}

// GetDN returns the entry's DN to delete
func (r *DeleteRequest) GetEntryDN() LDAPDN {
	return r.protocolOp
}

type DeleteResponse struct {
	ldapResult
	request *DeleteRequest
}

func (r *DeleteResponse) Send() {
	if r.request.out != nil {
		r.request.out <- *r
		r.request.wroteMessage++
	}
}

func (r DeleteResponse) encodeToAsn1() []byte {
	return newMessagePacket(r).Bytes()
}

// AddRequest is a definition of the Add Operation
type AddRequest struct {
	message
	protocolOp struct {
		entry      LDAPDN
		attributes AttributeList
	}
}

func (r *AddRequest) GetEntryDN() LDAPDN {
	return r.protocolOp.entry
}

func (r *AddRequest) GetAttributes() AttributeList {
	return r.protocolOp.attributes

}

type AddResponse struct {
	ldapResult
	request *AddRequest
}

func (r *AddResponse) Send() {
	if r.request.out != nil {
		r.request.out <- *r
		r.request.wroteMessage++
	}
}

func (r AddResponse) encodeToAsn1() []byte {
	return newMessagePacket(r).Bytes()
}

// SearchRequest is a definition of the Search Operation
// baseObject - The name of the base object entry (or possibly the root) relative to which the Search is to be performed
type SearchRequest struct {
	message
	protocolOp struct {
		BaseObject   []byte
		Scope        int
		DerefAliases int
		SizeLimit    int
		TimeLimit    int
		TypesOnly    bool
		Attributes   [][]byte
		Filter       string
	}
	searchResultDoneSent      bool
	searchResultEntrySent     int
	SearchResultReferenceSent int
}

func (s *SearchRequest) GetTypesOnly() bool {
	return s.protocolOp.TypesOnly
}

func (s *SearchRequest) GetAttributes() [][]byte {
	return s.protocolOp.Attributes
}
func (s *SearchRequest) GetFilter() string {
	return s.protocolOp.Filter
}
func (s *SearchRequest) GetBaseObject() []byte {
	return s.protocolOp.BaseObject
}
func (s *SearchRequest) GetScope() int {
	return s.protocolOp.Scope
}
func (s *SearchRequest) GetDerefAliases() int {
	return s.protocolOp.DerefAliases
}
func (s *SearchRequest) GetSizeLimit() int {
	return s.protocolOp.SizeLimit
}
func (s *SearchRequest) GetTimeLimit() int {
	return s.protocolOp.TimeLimit
}

func (s SearchRequest) String() string {
	var txt string

	txt = fmt.Sprintf("BaseObject:%s\nScope:%d\nDerefAliases:%d\nSizeLimit:%d\nTimeLimit:%d\nTypesOnly:%t\nFilter:%s\n",
		s.protocolOp.BaseObject,
		s.protocolOp.Scope,
		s.protocolOp.DerefAliases,
		s.protocolOp.SizeLimit,
		s.protocolOp.TimeLimit,
		s.protocolOp.TypesOnly,
		s.protocolOp.Filter)

	for i := range s.protocolOp.Attributes {
		txt = fmt.Sprintf("%sAttribute:%s\n", txt, s.protocolOp.Attributes[i])
	}

	return txt
}

// response is the interface implemented by each ldap response (BinResponse, SearchResponse, SearchEntryResult,...) struct
type response interface {
	encodeToAsn1() []byte
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

func (l ldapResult) encodeToAsn1() []byte {
	return newMessagePacket(l).Bytes()
}

// ExtendedResponse operation allows additional operations to be defined for
// services not already available in the protocol, like the disconnection
// notification sent by the server before it stops serving
// The Extended operation allows clients to receive
// responses with predefined syntaxes and semantics.  These may be
// defined in RFCs or be private to particular implementations.
type ExtendedResponse struct {
	ldapResult
	request       *BindRequest
	responseName  LDAPOID
	responseValue string
}

// ExtendedRequest operation allows additional operations to be defined for
// services not already available in the protocol
// The Extended operation allows clients to send request with predefined
// syntaxes and semantics.  These may be defined in RFCs or be private to
// particular implementations.
type ExtendedRequest struct {
	message
	protocolOp struct {
		requestName  LDAPOID
		requestValue string
	}
}

// AbandonRequest operation's function is allow a client to request
// that the server abandon an uncompleted operation.  The Abandon
// Request is defined as follows:
type AbandonRequest struct {
	message
	protocolOp int
}

// getIDToAbandon retrieves the message ID of the operation to abandon
func (r *AbandonRequest) getIDToAbandon() int {
	return r.protocolOp
}

// setIDToAbandon set the message ID of the operation to abandon
func (r *AbandonRequest) setIDToAbandon(ID int) {
	r.protocolOp = ID
}

// BindResponse consists simply of an indication from the server of the
// status of the client's request for authentication
type BindResponse struct {
	ldapResult
	request         *BindRequest
	serverSaslCreds string
}

func (r *BindResponse) Send() {
	if r.request.out != nil {
		r.request.out <- *r
		r.request.wroteMessage++
	}
}

func (r *SearchResponse) Send() {
	if r.request.out != nil {
		r.request.out <- *r
		r.request.wroteMessage++
	}
}

func (r SearchResponse) encodeToAsn1() []byte {
	return newMessagePacket(r).Bytes()
}

func (r BindResponse) encodeToAsn1() []byte {
	return newMessagePacket(r).Bytes()
}

func (r BindResponse) String() string {
	return ""
}

type SearchResponse struct {
	ldapResult
	request   *SearchRequest
	referrals []string
	//Controls []Control
}

func (r *SearchResponse) SendEntry(entry *SearchResultEntry) {
	entry.request = r.request
	if r.request.out != nil {
		r.request.out <- *entry //NOTE : Why do i need to * a *SearchResultEntry ?
		r.request.searchResultEntrySent++
		r.request.wroteMessage++
	}
}

func (r *SearchResponse) SendResultDone(ldapCode int, message string) {
	r.ResultCode = ldapCode
	r.DiagnosticMessage = message
	r.Send()
	r.request.searchResultDoneSent = true
}

func (r SearchResponse) String() string {
	return ""
}

// SearchResultEntry represents an entry found during the Search
type SearchResultEntry struct {
	request    *SearchRequest
	dN         string
	attributes []*entryAttribute
}

func (e *SearchResultEntry) SetDn(dn string) {
	e.dN = dn
}

func (e *SearchResultEntry) AddAttribute(name string, values ...string) {
	var ea = &entryAttribute{Name: name, Values: values}
	e.attributes = append(e.attributes, ea)
}

func (r ExtendedResponse) encodeToAsn1() []byte {
	return newMessagePacket(r).Bytes()
}
func (e SearchResultEntry) encodeToAsn1() []byte {
	return newMessagePacket(e).Bytes()
}

type entryAttribute struct {
	Name   string
	Values []string
}
