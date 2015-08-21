package ldapserver

import roox "github.com/vjeantet/goldap/message"

func NewBindResponse(resultCode int) roox.BindResponse {
	r := roox.BindResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewResponse(resultCode int) roox.LDAPResult {
	r := roox.LDAPResult{}
	r.SetResultCode(resultCode)
	return r
}

func NewExtendedResponse(resultCode int) roox.ExtendedResponse {
	r := roox.ExtendedResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewCompareResponse(resultCode int) roox.CompareResponse {
	r := roox.CompareResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewModifyResponse(resultCode int) roox.ModifyResponse {
	r := roox.ModifyResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewDeleteResponse(resultCode int) roox.DelResponse {
	r := roox.DelResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewAddResponse(resultCode int) roox.AddResponse {
	r := roox.AddResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewSearchResultDoneResponse(resultCode int) roox.SearchResultDone {
	r := roox.SearchResultDone{}
	r.SetResultCode(resultCode)
	return r
}

func NewSearchResultEntry(objectname string) roox.SearchResultEntry {
	r := roox.SearchResultEntry{}
	r.SetObjectName(objectname)
	return r
}
