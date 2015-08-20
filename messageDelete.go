package ldapserver

// DeleteRequest is a definition of the Delete Operation

type DeleteResponse struct {
	ldapResult
}

func NewDeleteResponse(resultCode int) *DeleteResponse {
	r := &DeleteResponse{}
	r.ResultCode = resultCode
	return r
}
