package ldapserver

import roox "github.com/vjeantet/goldap/message"

type ModifyRequest struct {
	roox.ModifyRequest
}

type ModifyResponse struct {
	ldapResult
}

func NewModifyResponse(resultCode int) *ModifyResponse {
	r := &ModifyResponse{}
	r.ResultCode = resultCode
	return r
}
