package ldapserver

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

// SearchResultEntry represents an entry found during the Search
type SearchResultEntry struct {
	request    *SearchRequest
	dN         string
	attributes PartialAttributeList
}

func (e *SearchResultEntry) SetDn(dn string) {
	e.dN = dn
}

func (e *SearchResultEntry) AddAttribute(name AttributeDescription, values ...AttributeValue) {
	var ea = PartialAttribute{type_: name, vals: values}
	e.attributes.add(ea)
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

func (r *SearchResponse) Send() {
	if r.request.out != nil {
		r.request.out <- *r
		r.request.wroteMessage++
	}
}
