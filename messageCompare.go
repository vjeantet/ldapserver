package ldapserver

type CompareResponse struct {
	ldapResult
}

func NewCompareResponse(resultCode int) *CompareResponse {
	r := &CompareResponse{}
	r.ResultCode = resultCode
	return r
}
