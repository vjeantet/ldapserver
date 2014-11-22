package ldapserver

type CompareRequest struct {
	entry LDAPDN
	ava   AttributeValueAssertion
}

func (r *CompareRequest) GetEntry() LDAPDN {
	return r.entry
}

func (r *CompareRequest) GetAttributeValueAssertion() *AttributeValueAssertion {
	return &r.ava
}

type CompareResponse struct {
	ldapResult
}

func NewCompareResponse(messageID int, resultCode int) CompareResponse {
	r := CompareResponse{}
	r.MessageID = messageID
	r.ResultCode = resultCode
	return r
}
