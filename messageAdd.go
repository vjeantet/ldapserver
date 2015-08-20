package ldapserver

import roox "github.com/vjeantet/goldap/message"

// AddRequest is a definition of the Add Operation
type AddRequest struct {
	roox.AddRequest
}

type AddResponse struct {
	ldapResult
}

func NewAddResponse(resultCode int) *AddResponse {
	r := &AddResponse{}
	r.ResultCode = resultCode
	return r
}
