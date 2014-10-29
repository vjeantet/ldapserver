package ldapserver

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
