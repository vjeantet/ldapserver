package ldapserver

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
