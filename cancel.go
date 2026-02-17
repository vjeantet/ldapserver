package ldapserver

import (
	"encoding/asn1"
	"fmt"

	ldap "github.com/lor00x/goldap/message"
)

// cancelRequestValue represents the ASN.1 value of a Cancel Extended Request
// per RFC 3909: cancelRequestValue ::= SEQUENCE { cancelID MessageID }
type cancelRequestValue struct {
	CancelID int
}

// parseCancelRequestValue decodes the cancelID from the BER-encoded
// requestValue of a Cancel Extended Request (OID 1.3.6.1.1.8).
func parseCancelRequestValue(raw *ldap.OCTETSTRING) (int, error) {
	if raw == nil {
		return 0, fmt.Errorf("cancel request: missing requestValue")
	}

	var val cancelRequestValue
	rest, err := asn1.Unmarshal([]byte(*raw), &val)
	if err != nil {
		return 0, fmt.Errorf("cancel request: failed to decode requestValue: %w", err)
	}
	if len(rest) > 0 {
		return 0, fmt.Errorf("cancel request: trailing data after requestValue")
	}
	if val.CancelID < 1 {
		return 0, fmt.Errorf("cancel request: invalid cancelID %d", val.CancelID)
	}
	return val.CancelID, nil
}

// handleCancel is the built-in handler for the Cancel Extended Operation
// (RFC 3909, OID 1.3.6.1.1.8). It signals the target operation to abort
// and responds with an ExtendedResponse.
func handleCancel(w ResponseWriter, r *Message) {
	req := r.GetExtendedRequest()

	cancelID, err := parseCancelRequestValue(req.RequestValue())
	if err != nil {
		res := NewExtendedResponse(LDAPResultProtocolError)
		res.SetDiagnosticMessage(err.Error())
		w.Write(res)
		return
	}

	// Look up the target message
	target, ok := r.Client.GetMessageByID(cancelID)
	if !ok {
		res := NewExtendedResponse(LDAPResultNoSuchOperation)
		w.Write(res)
		return
	}

	// Check for non-cancelable operations per RFC 3909 section 2.
	// Unbind is not checked because it causes immediate disconnect
	// and is never in requestList.
	switch target.ProtocolOp().(type) {
	case ldap.BindRequest, ldap.AbandonRequest:
		res := NewExtendedResponse(LDAPResultCannotCancel)
		w.Write(res)
		return
	case ldap.ExtendedRequest:
		ext := target.GetExtendedRequest()
		name := ext.RequestName()
		if name == NoticeOfStartTLS || name == NoticeOfCancel {
			res := NewExtendedResponse(LDAPResultCannotCancel)
			w.Write(res)
			return
		}
	}

	// Signal the target to abort
	target.Abandon()

	res := NewExtendedResponse(LDAPResultCanceled)
	w.Write(res)
}
