package ldapserver

import "log"

type RequestHandler interface {
	bind(w BindResponse, r *BindRequest)
	search(w SearchResponse, r *SearchRequest)
	add(w AddResponse, r *AddRequest)
	delete(w DeleteResponse, r *DeleteRequest)
	modify(w ModifyResponse, r *ModifyRequest)
	extended(w ExtendedResponse, r *ExtendedRequest)
	compare(w CompareResponse, r *CompareRequest)
	//abandon
	//unbind
	unknow(r *request)
	SetBindFunc(f func(BindResponse, *BindRequest))
	SetSearchFunc(f func(SearchResponse, *SearchRequest))
	SetAddFunc(f func(AddResponse, *AddRequest))
	SetDeleteFunc(f func(DeleteResponse, *DeleteRequest))
	SetModifyFunc(f func(ModifyResponse, *ModifyRequest))
	SetCompareFunc(f func(CompareResponse, *CompareRequest))
	SetExtendedFunc(f func(ExtendedResponse, *ExtendedRequest))
}

type DefaultHandler struct {
	bindF     func(BindResponse, *BindRequest)
	searchF   func(SearchResponse, *SearchRequest)
	addF      func(AddResponse, *AddRequest)
	deleteF   func(DeleteResponse, *DeleteRequest)
	modifyF   func(ModifyResponse, *ModifyRequest)
	compareF  func(CompareResponse, *CompareRequest)
	extendedF func(ExtendedResponse, *ExtendedRequest)
}

func (h *DefaultHandler) SetBindFunc(f func(BindResponse, *BindRequest)) {
	h.bindF = f
}

func (h *DefaultHandler) SetSearchFunc(f func(SearchResponse, *SearchRequest)) {
	h.searchF = f
}

func (h *DefaultHandler) SetAddFunc(f func(AddResponse, *AddRequest)) {
	h.addF = f
}
func (h *DefaultHandler) SetDeleteFunc(f func(DeleteResponse, *DeleteRequest)) {
	h.deleteF = f
}

func (h *DefaultHandler) SetModifyFunc(f func(ModifyResponse, *ModifyRequest)) {
	h.modifyF = f
}

func (h *DefaultHandler) SetCompareFunc(f func(CompareResponse, *CompareRequest)) {
	h.compareF = f
}

func (h *DefaultHandler) SetExtendedFunc(f func(ExtendedResponse, *ExtendedRequest)) {
	h.extendedF = f
}

func (h *DefaultHandler) unknow(r *request) {
	//TODO: send a protocolErrorResponse
	log.Printf("WARNING : unexpected request type %V", r)
}

// handleBindRequest is the default handler for BindRequests, It always
// returns a Success
// use Server.SetBindHandler() to implement a custom handler
func (h *DefaultHandler) bind(w BindResponse, r *BindRequest) {
	if h.bindF != nil {
		h.bindF(w, r)
		return
	}
	w.ResultCode = LDAPResultSuccess
	w.Send()
	return
}

// search is the default handler for SearchRequest, It always
// returns a Success with no entries
// It handles Search's operations used to request a server to return, subject
// to access controls and other restrictions, a set of entries matching
// a complex search criterion.  This can be used to read attributes from
// a single entry, from entries immediately subordinate to a particular
// entry, or from a whole subtree of entries.
// Use the SearchResponse to send all SearchResultEntry
// The fn func should take care of timeLimit and sizeLimit and send the adequats Ldap Response
// LDAPResultTimeLimitExceeded, LDAPResultSizeLimitExceeded, ....
// The fn func should set the result code to send back to the client, if eerything is ok, a resultCode set
// to LDAPResultSuccess
// Listen to *SearchRequest.GetDoneChannel() channel, when a value comes out of this
// channel it means that responses may consumed by the client, because of a AbandonRequest,
// a Server stop, etc....
func (h *DefaultHandler) search(w SearchResponse, r *SearchRequest) {
	if h.searchF != nil {
		h.searchF(w, r)
		return
	}

	w.ResultCode = LDAPResultSuccess
	w.Send()
	return
}

func (h *DefaultHandler) add(w AddResponse, r *AddRequest) {
	w.ResultCode = LDAPResultOperationsError
	w.Send()
	return
}

func (h *DefaultHandler) delete(w DeleteResponse, r *DeleteRequest) {
	w.ResultCode = LDAPResultOperationsError
	w.Send()
	return
}

func (h *DefaultHandler) modify(w ModifyResponse, r *ModifyRequest) {
	w.ResultCode = LDAPResultOperationsError
	w.Send()
	return
}

func (h *DefaultHandler) extended(w ExtendedResponse, r *ExtendedRequest) {
	w.ResultCode = LDAPResultOperationsError
	w.Send()
}

func (h *DefaultHandler) compare(w CompareResponse, r *CompareRequest) {
	w.ResultCode = LDAPResultOperationsError
	w.Send()
	return
}
