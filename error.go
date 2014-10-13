package ldapserver

func BindError(r BindResponse, ldapCode int, error string) {
	r.ResultCode = ldapCode
	r.DiagnosticMessage = error
	r.Send()
}

func SearchError(r SearchResponse, ldapCode int, error string) {
	r.ResultCode = ldapCode
	r.DiagnosticMessage = error
	r.Send()
}
