package ldapserver

// write a LDAP error to the client as the BindResponse
func BindError(r BindResponse, ldapCode int, errorMsg string) {
	r.ResultCode = ldapCode
	r.DiagnosticMessage = errorMsg
	r.Send()
}

// write a LDAP error to the client as the SearchResponse
func SearchError(r SearchResponse, ldapCode int, errorMsg string) {
	r.ResultCode = ldapCode
	r.DiagnosticMessage = errorMsg
	r.Send()
}
