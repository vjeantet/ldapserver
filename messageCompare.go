package ldapserver

type CompareRequest struct {
	message
	protocolOp struct {
		entry LDAPDN
		ava   AttributeValueAssertion
	}
}

func (r *CompareRequest) GetEntry() LDAPDN {
	return r.protocolOp.entry
}

func (r *CompareRequest) GetAttributeValueAssertion() *AttributeValueAssertion {
	return &r.protocolOp.ava
}

type CompareResponse struct {
	ldapResult
	request *CompareRequest
}

func (r *CompareResponse) Send() {
	if r.request.out != nil {
		r.request.out <- *r
		r.request.wroteMessage++
	}
}
