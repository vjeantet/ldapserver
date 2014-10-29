package ldapserver

// ExtendedRequest operation allows additional operations to be defined for
// services not already available in the protocol
// The Extended operation allows clients to send request with predefined
// syntaxes and semantics.  These may be defined in RFCs or be private to
// particular implementations.
type ExtendedRequest struct {
	message
	protocolOp struct {
		requestName  LDAPOID
		requestValue []byte
	}
}

func (r *ExtendedRequest) GetResponseName() LDAPOID {
	return r.protocolOp.requestName
}

func (r *ExtendedRequest) GetResponseValue() []byte {
	return r.protocolOp.requestValue
}

// ExtendedResponse operation allows additional operations to be defined for
// services not already available in the protocol, like the disconnection
// notification sent by the server before it stops serving
// The Extended operation allows clients to receive
// responses with predefined syntaxes and semantics.  These may be
// defined in RFCs or be private to particular implementations.
type ExtendedResponse struct {
	ldapResult
	request       *ExtendedRequest
	responseName  LDAPOID
	responseValue string
}

func (r *ExtendedResponse) Send() {
	if r.request.out != nil {
		r.request.out <- *r
		r.request.wroteMessage++
	}
}
