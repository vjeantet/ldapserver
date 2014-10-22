package ldapserver

import "fmt"

type protocolOp interface {
	String() string
}

type request interface {
	GetMessageId() int
	String() string
	GetProtocolOp() protocolOp
}

type message struct {
	wroteMessage int
	messageId    int
	protocolOp   protocolOp
	Controls     []interface{}
	out          chan response
}

func (m message) GetMessageId() int {
	return m.messageId
}

func (m message) String() string {
	return fmt.Sprintf("MessageId=%d, %s", m.messageId, m.protocolOp.String())
}
func (m message) GetProtocolOp() protocolOp {
	return m.protocolOp
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
	var s string = ""

	s = fmt.Sprintf("Login:%s, Password:%s",
		r.GetLogin(),
		r.GetPassword())

	return s
}

// UNBIND REQUEST message
type UnbindRequest struct {
	message
	protocolOp struct {
	}
}

// a SearchRequest message struct
type SearchRequest struct {
	message
	protocolOp struct {
		BaseDN       []byte
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
func (s *SearchRequest) GetBaseDN() []byte {
	return s.protocolOp.BaseDN
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

func (r SearchRequest) String() string {
	var s string = ""

	s = fmt.Sprintf("BaseDn:%s\nScope:%d\nDerefAliases:%d\nSizeLimit:%d\nTimeLimit:%d\nTypesOnly:%t\nFilter:%s\n",
		r.protocolOp.BaseDN,
		r.protocolOp.Scope,
		r.protocolOp.DerefAliases,
		r.protocolOp.SizeLimit,
		r.protocolOp.TimeLimit,
		r.protocolOp.TypesOnly,
		r.protocolOp.Filter)

	for i := range r.protocolOp.Attributes {
		s = fmt.Sprintf("%sAttribute:%s\n", s, r.protocolOp.Attributes[i])
	}

	return s
}

// REPONSES
type response interface {
	encodeToAsn1() []byte
}
type ldapResult struct {
	ResultCode        int
	MatchedDN         string
	DiagnosticMessage string
	referral          interface{}
}

func (l ldapResult) encodeToAsn1() []byte {
	return newMessagePacket(l).Bytes()
}

// BindResponse
type BindResponse struct {
	ldapResult
	request         *BindRequest
	serverSaslCreds string
}

func (r *BindResponse) Send() {
	if r.request.out != nil {
		r.request.out <- r
		r.request.wroteMessage += 1
	}
}

func (r *SearchResponse) Send() {
	if r.request.out != nil {
		r.request.out <- r
		r.request.wroteMessage += 1
	}
}

func (sr SearchResponse) encodeToAsn1() []byte {
	return newMessagePacket(sr).Bytes()
}

func (b BindResponse) encodeToAsn1() []byte {
	return newMessagePacket(b).Bytes()
}

func (r BindResponse) String() string {
	return ""
}

type SearchResponse struct {
	ldapResult
	request   *SearchRequest
	referrals []string
	//Controls []Control
	chan_out chan response
}

func (r *SearchResponse) SendEntry(entry *SearchResultEntry) {
	entry.request = r.request
	if r.request.out != nil {
		r.request.out <- *entry //NOTE : Why do i need to * a *SearchResultEntry ?
		r.request.searchResultEntrySent += 1
		r.request.wroteMessage += 1
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

func (e SearchResultEntry) encodeToAsn1() []byte {
	return newMessagePacket(e).Bytes()
}

type entryAttribute struct {
	Name   string
	Values []string
}
