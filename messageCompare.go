package ldapserver

import roox "github.com/vjeantet/goldap/message"

type CompareRequest struct {
	roox.CompareRequest
}

type CompareResponse struct {
	ldapResult
}

func NewCompareResponse(resultCode int) *CompareResponse {
	r := &CompareResponse{}
	r.ResultCode = resultCode
	return r
}
