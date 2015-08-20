package ldapserver

type AddResponse struct {
	ldapResult
}

func NewAddResponse(resultCode int) *AddResponse {
	r := &AddResponse{}
	r.ResultCode = resultCode
	return r
}
