package ldapserver

// AddRequest is a definition of the Add Operation
type AddRequest struct {
	entry      LDAPDN
	attributes AttributeList
}

func (r *AddRequest) GetEntryDN() LDAPDN {
	return r.entry
}

func (r *AddRequest) GetAttributes() AttributeList {
	return r.attributes

}

type AddResponse struct {
	ldapResult
	request *AddRequest
}

func NewAddResponse(messageID int, resultCode int) AddResponse {
	r := AddResponse{}
	r.MessageID = messageID
	r.ResultCode = resultCode
	return r
}
