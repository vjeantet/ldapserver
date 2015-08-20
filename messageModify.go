package ldapserver

type ModifyResponse struct {
	ldapResult
}

func NewModifyResponse(resultCode int) *ModifyResponse {
	r := &ModifyResponse{}
	r.ResultCode = resultCode
	return r
}
