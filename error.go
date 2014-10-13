package ldap

type Error struct {
	Err        error
	ResultCode uint8
}

func NewError(ResultCode uint8, Err error) *Error {
	return &Error{ResultCode: ResultCode, Err: Err}
}

func BindError(r BindResponse, error string, ldapCode int) {
	r.ResultCode = ldapCode
	r.DiagnosticMessage = error
	r.Send()
}
