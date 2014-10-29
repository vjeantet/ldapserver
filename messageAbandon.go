package ldapserver

// AbandonRequest operation's function is allow a client to request
// that the server abandon an uncompleted operation.  The Abandon
// Request is defined as follows:
type AbandonRequest struct {
	message
	protocolOp int
}

// getIDToAbandon retrieves the message ID of the operation to abandon
func (r *AbandonRequest) getIDToAbandon() int {
	return r.protocolOp
}

// setIDToAbandon set the message ID of the operation to abandon
func (r *AbandonRequest) setIDToAbandon(ID int) {
	r.protocolOp = ID
}
