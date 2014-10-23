package ldapserver

import "fmt"

type protocolOp interface {
	String() string
}

type request interface {
	getMessageID() int
	String() string
	getProtocolOp() protocolOp
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

func (m *message) GetDoneSignal() chan bool {
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

func (s SearchRequest) String() string {
	var txt string

	txt = fmt.Sprintf("BaseDn:%s\nScope:%d\nDerefAliases:%d\nSizeLimit:%d\nTimeLimit:%d\nTypesOnly:%t\nFilter:%s\n",
		s.protocolOp.BaseDN,
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
