package ldapserver

// handleBindRequest is the default handler for BindRequests, It always
// returns a Success
// use Server.SetBindHandler() to implement a custom handler
func handleBindRequest(w BindResponse, r *BindRequest) {
	w.ResultCode = LDAPResultSuccess
	w.Send()
	return
}

// handleSearchRequest is the default handler for SearchRequest, It always
// returns a Success with no entries
// use Server.SetSearchHandler() to implement a custom handler
func handleSearchRequest(w SearchResponse, r *SearchRequest) {
	w.ResultCode = LDAPResultSuccess
	w.Send()
	return
}

func handleAddRequest(w AddResponse, r *AddRequest) {
	w.ResultCode = LDAPResultOperationsError
	w.Send()
	return
}

func handleDeleteRequest(w DeleteResponse, r *DeleteRequest) {
	w.ResultCode = LDAPResultOperationsError
	w.Send()
	return
}

func handleModifyRequest(w ModifyResponse, r *ModifyRequest) {
	w.ResultCode = LDAPResultOperationsError
	w.Send()
	return
}

func handleExtendedRequest(w ExtendedResponse, r *ExtendedRequest) {
	w.ResultCode = LDAPResultOperationsError
	w.Send()
}

func handleCompareRequest(w CompareResponse, r *CompareRequest) {
	w.ResultCode = LDAPResultOperationsError
	w.Send()
	return
}
