package ldapserver

// BindResponse consists simply of an indication from the server of the
// status of the client's request for authentication
type BindResponse struct {
	ldapResult
	serverSaslCreds string
}

func NewBindResponse(resultCode int) *BindResponse {
	r := &BindResponse{}
	r.ResultCode = resultCode
	return r
}
