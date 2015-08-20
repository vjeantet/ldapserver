package ldapserver

import roox "github.com/vjeantet/goldap/message"

// SearchRequest is a definition of the Search Operation
// baseObject - The name of the base object entry (or possibly the root) relative to which the Search is to be performed
type SearchRequest struct {
	roox.SearchRequest
}

// SearchResultEntry represents an entry found during the Search
type SearchResultEntry struct {
	MessageID  int
	dN         string
	attributes PartialAttributeList
}

func (e *SearchResultEntry) SetMessageID(ID int) {
	e.MessageID = ID
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
	referrals []string
	//Controls []Control
}

func NewSearchResultDoneResponse(resultCode int) *SearchResponse {
	r := &SearchResponse{}
	r.ResultCode = resultCode
	return r
}

func NewSearchResultEntry() *SearchResultEntry {
	r := &SearchResultEntry{}
	return r
}
