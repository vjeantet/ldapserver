package ldapserver

// request is the interface implemented by each ldap request (BinRequest, SearchRequest, ...) struct
type request interface {
	getMessageID() int
	String() string
	getProtocolOp() protocolOp
	abort()
}

// response is the interface implemented by each ldap response (BinResponse, SearchResponse, SearchEntryResult,...) struct
type response interface {
}

// ldapResult is the construct used in LDAP protocol to return
// success or failure indications from servers to clients.  To various
// requests, servers will return responses containing the elements found
// in LDAPResult to indicate the final status of the protocol operation
// request.
type ldapResult struct {
	ResultCode        int
	MatchedDN         LDAPDN
	DiagnosticMessage string
	referral          interface{}
}
