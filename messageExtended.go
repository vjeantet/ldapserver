package ldapserver

import roox "github.com/vjeantet/goldap/message"

// ExtendedRequest operation allows additional operations to be defined for
// services not already available in the protocol
// The Extended operation allows clients to send request with predefined
// syntaxes and semantics.  These may be defined in RFCs or be private to
// particular implementations.
type ExtendedRequest struct {
	roox.ExtendedRequest
}

// ExtendedResponse operation allows additional operations to be defined for
// services not already available in the protocol, like the disconnection
// notification sent by the server before it stops serving
// The Extended operation allows clients to receive
// responses with predefined syntaxes and semantics.  These may be
// defined in RFCs or be private to particular implementations.
type ExtendedResponse struct {
	ldapResult
	ResponseName  string
	ResponseValue string
}

func NewExtendedResponse(resultCode int) *ExtendedResponse {
	r := &ExtendedResponse{}
	r.ResultCode = resultCode
	return r
}
