package ldapserver

// DeleteRequest is a definition of the Delete Operation
type DeleteRequest LDAPDN

// GetDN returns the entry's DN to delete
func (r *DeleteRequest) GetEntryDN() LDAPDN {
	return LDAPDN(*r)
}

type DeleteResponse struct {
	ldapResult
	request *DeleteRequest
}

func NewDeleteResponse(messageID int, resultCode int) DeleteResponse {
	r := DeleteResponse{}
	r.MessageID = messageID
	r.ResultCode = resultCode
	return r
}
