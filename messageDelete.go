package ldapserver

import roox "github.com/vjeantet/goldap/message"

// DeleteRequest is a definition of the Delete Operation
type DeleteRequest roox.DelRequest

type DeleteResponse struct {
	ldapResult
}

func NewDeleteResponse(resultCode int) *DeleteResponse {
	r := &DeleteResponse{}
	r.ResultCode = resultCode
	return r
}
