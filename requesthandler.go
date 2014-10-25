package ldapserver

func handleBindRequest(w BindResponse, r *BindRequest) {
	w.ResultCode = LDAPResultSuccess
	w.Send()
	return
}

func handleSearchRequest(w SearchResponse, r *SearchRequest) {
	w.ResultCode = LDAPResultSuccess
	w.Send()
	return
}
