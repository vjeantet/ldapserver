package ldapserver

import roox "github.com/vjeantet/goldap/message"

// BindRequest struct
type BindRequest struct {
	roox.BindRequest
}

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

func (r *BindResponse) Bytes() []byte {
	return newMessagePacket(r).Bytes()
}
