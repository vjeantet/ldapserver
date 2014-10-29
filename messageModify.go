package ldapserver

type ModifyRequest struct {
	message
	protocolOp struct {
		object  LDAPDN
		changes []modifyRequestChange
	}
}

func (r *ModifyRequest) GetChanges() []modifyRequestChange {
	return r.protocolOp.changes
}

func (r *ModifyRequest) GetObject() LDAPDN {
	return r.protocolOp.object
}

type modifyRequestChange struct {
	operation    int
	modification PartialAttribute
}

func (r *modifyRequestChange) GetModification() PartialAttribute {
	return r.modification
}

func (r *modifyRequestChange) GetOperation() int {
	return r.operation
}

type ModifyResponse struct {
	ldapResult
	request *ModifyRequest
}

func (r *ModifyResponse) Send() {
	if r.request.out != nil {
		r.request.out <- *r
		r.request.wroteMessage++
	}
}
