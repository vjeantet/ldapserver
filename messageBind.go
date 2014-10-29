package ldapserver

import "fmt"

// a BindRequest struct
type BindRequest struct {
	message
	protocolOp struct {
		Version  int
		Login    []byte
		Password []byte
	}
}

func (r *BindRequest) SetLogin(login []byte) {
	r.protocolOp.Login = login
}

func (r *BindRequest) GetLogin() []byte {
	return r.protocolOp.Login
}

func (r *BindRequest) SetVersion(version int) {
	r.protocolOp.Version = version
}

func (r *BindRequest) SetPassword(password []byte) {
	r.protocolOp.Password = password
}

func (r *BindRequest) GetPassword() []byte {
	return r.protocolOp.Password
}

func (r BindRequest) String() string {
	var s string

	s = fmt.Sprintf("Login:%s, Password:%s",
		r.GetLogin(),
		r.GetPassword())

	return s
}

// BindResponse consists simply of an indication from the server of the
// status of the client's request for authentication
type BindResponse struct {
	ldapResult
	request         *BindRequest
	serverSaslCreds string
}

func (r BindResponse) String() string {
	return ""
}

func (r *BindResponse) Send() {
	if r.request.out != nil {
		r.request.out <- *r
		r.request.wroteMessage++
	}
}
