package ldapserver

import (
	"bufio"
	"errors"
	"fmt"
	"log"

	ber "github.com/vjeantet/asn1-ber"
	roox "github.com/vjeantet/goldap/message"
)

type messagePacket struct {
	bytes []byte
}

func readMessagePacket(br *bufio.Reader) (*messagePacket, error) {
	var err error
	var bytes *[]byte
	bytes, err = readLdapMessageBytes(br)

	messagePacket := &messagePacket{bytes: *bytes}
	return messagePacket, err
}

func (msg *messagePacket) readMessage() (m Message, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid packet received hex=%x, %#v", msg.bytes, r)
		}
	}()

	rMessage, err := decodeMessage(msg.bytes)
	m.MessageID = int(rMessage.MessageID())

	if rMessage.Controls() != nil {
		for _, control := range *rMessage.Controls() {
			c := Control{
				controlType: string(control.ControlType()),
				criticality: bool(control.Criticality()),
			}
			if control.ControlValue() != nil {
				c.controlValue = string(*control.ControlValue())
			}

			m.Controls = append(m.Controls, c)
		}
	}

	switch rMessage.ProtocolOp().(type) {
	case roox.BindRequest:
		ii := rMessage.ProtocolOp().(roox.BindRequest)
		m.protocolOp = BindRequest{
			Login:    []byte(ii.Name()),
			Password: []byte(ii.Authentication().(roox.OCTETSTRING)),
		}
		return m, nil
	case roox.UnbindRequest:
		m.protocolOp = UnbindRequest{}
		return m, nil
	case roox.AbandonRequest:
		ii := rMessage.ProtocolOp().(roox.AbandonRequest)
		m.protocolOp = AbandonRequest(ii)
		return m, nil
	case roox.DelRequest:
		ii := rMessage.ProtocolOp().(roox.DelRequest)
		m.protocolOp = DeleteRequest(ii)
		return m, nil
	case roox.ExtendedRequest:
		ii := rMessage.ProtocolOp().(roox.ExtendedRequest)

		er := ExtendedRequest{}
		er.requestName = string(ii.RequestName())
		if ii.RequestValue() != nil {
			er.requestValue = []byte(*ii.RequestValue())
		}

		m.protocolOp = er
		return m, nil
	case roox.CompareRequest:
		ii := rMessage.ProtocolOp().(roox.CompareRequest)
		m.protocolOp = CompareRequest{
			entry: LDAPDN(ii.Entry()),
			ava: AttributeValueAssertion{
				attributeDesc:  AttributeDescription(ii.Ava().AttributeDesc()),
				assertionValue: AssertionValue(ii.Ava().AssertionValue()),
			},
		}
		return m, nil
	case roox.SearchRequest:

		ii := rMessage.ProtocolOp().(roox.SearchRequest)
		sr := SearchRequest{}

		sr.BaseObject = []byte(ii.BaseObject())
		sr.Scope = int(ii.Scope())
		sr.DerefAliases = int(ii.DerefAliases())
		sr.SizeLimit = int(ii.SizeLimit())
		sr.TimeLimit = int(ii.TimeLimit())
		sr.TypesOnly = bool(ii.TypesOnly())

		for _, attribute := range ii.Attributes() {
			sr.Attributes = append(
				sr.Attributes,
				[]byte(attribute),
			)
		}

		var ldaperr error
		sr.Filter, ldaperr = decompileFilter(ii.Filter())
		if ldaperr != nil {
			log.Printf("error decompiling searchrequestfilter %s", ldaperr)
		}

		m.protocolOp = sr
		return m, nil

	case roox.AddRequest:
		ii := rMessage.ProtocolOp().(roox.AddRequest)
		var r AddRequest
		r.entry = LDAPDN(ii.Entry())
		for _, attribute := range ii.Attributes() {
			rattribute := Attribute{
				type_: AttributeDescription(attribute.Type_()),
			}

			for _, val := range attribute.Vals() {
				rattribute.vals = append(
					rattribute.vals,
					AttributeValue(val),
				)
			}
			r.attributes = append(r.attributes, rattribute)
		}

		m.protocolOp = r
		return m, nil

	case roox.ModifyRequest:
		ii := rMessage.ProtocolOp().(roox.ModifyRequest)
		var r ModifyRequest
		r.object = LDAPDN(ii.Object())

		for _, change := range ii.Changes() {
			operation := int(change.Operation())
			attributeName := change.Modification().Type_()
			modifyRequestChange := modifyRequestChange{operation: operation}
			rattribute := PartialAttribute{type_: AttributeDescription(attributeName)}
			for _, val := range change.Modification().Vals() {
				rattribute.vals = append(rattribute.vals, AttributeValue(val))
			}
			modifyRequestChange.modification = rattribute
			r.changes = append(r.changes, modifyRequestChange)

		}

		m.protocolOp = r
		return m, nil
	}

	return m, fmt.Errorf("unknow ldap operation [operation=%#v]", rMessage)
}

func decompileFilter(packet roox.Filter) (ret string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("error decompiling filter")
		}
	}()

	ret = "("
	err = nil
	childStr := ""

	switch f := packet.(type) {
	case roox.FilterAnd:
		ret += "&"
		for _, child := range f {
			childStr, err = decompileFilter(child)
			if err != nil {
				return
			}
			ret += childStr
		}
	case roox.FilterOr:
		ret += "|"
		for _, child := range f {
			childStr, err = decompileFilter(child)
			if err != nil {
				return
			}
			ret += childStr
		}
	case roox.FilterNot:
		ret += "!"
		childStr, err = decompileFilter(f)
		if err != nil {
			return
		}
		ret += childStr

	case roox.FilterSubstrings:
		ret += string(f.Type_())
		ret += "="
		for _, fs := range f.Substrings() {
			switch fsv := fs.(type) {
			case roox.SubstringInitial:
				ret += string(fsv) + "*"
			case roox.SubstringAny:
				ret += "*" + string(fsv) + "*"
			case roox.SubstringFinal:
				ret += "*" + string(fsv)
			}
		}
	case roox.FilterEqualityMatch:
		ret += string(f.AttributeDesc())
		ret += "="
		ret += string(f.AssertionValue())
	case roox.FilterGreaterOrEqual:
		ret += string(f.AttributeDesc())
		ret += ">="
		ret += string(f.AssertionValue())
	case roox.FilterLessOrEqual:
		ret += string(f.AttributeDesc())
		ret += "<="
		ret += string(f.AssertionValue())
	case roox.FilterPresent:
		// if 0 == len(packet.Children) {
		// 	ret += ber.DecodeString(packet.Data.Bytes())
		// } else {
		// 	ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		// }
		ret += string(f)
		ret += "=*"
	case roox.FilterApproxMatch:
		ret += string(f.AttributeDesc())
		ret += "~="
		ret += string(f.AssertionValue())
	}

	ret += ")"
	return
}

func newMessagePacket(lr response) *ber.Packet {
	switch v := lr.(type) {
	case *BindResponse:
		var b = lr.(*BindResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(b.MessageID), "MessageID"))
		bindResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
		bindResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(b.ResultCode), "ResultCode"))
		bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(b.MatchedDN), "MatchedDN"))
		bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, b.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(bindResponse)
		return packet

	case *SearchResponse:
		var res = lr.(*SearchResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(res.MessageID), "MessageID"))
		searchResultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultDone, nil, "Search done")
		searchResultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(res.ResultCode), "ResultCode"))
		searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(res.MatchedDN), "MatchedDN"))
		searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, res.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(searchResultDone)
		return packet

	case *SearchResultEntry:
		var s = lr.(*SearchResultEntry)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(s.MessageID), "MessageID"))
		searchResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "SearchResultEntry")
		searchResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, s.dN, "LDAPDN"))
		attributesList := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes List")
		for j := range s.attributes {
			attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
			attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(s.attributes[j].GetDescription()), "type"))
			values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
			for k := range s.attributes[j].vals {
				values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(s.attributes[j].vals[k]), "val"))
			}
			attributes.AppendChild(values)
			attributesList.AppendChild(attributes)

		}
		searchResponse.AppendChild(attributesList)
		packet.AppendChild(searchResponse)
		return packet

	case *ExtendedResponse:
		var b = lr.(*ExtendedResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(b.MessageID), "MessageID"))
		extendedResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedResponse, nil, "Extended Response")
		extendedResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(b.ResultCode), "ResultCode"))
		extendedResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(b.MatchedDN), "MatchedDN"))
		extendedResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, b.DiagnosticMessage, "DiagnosticMessage"))
		extendedResponse.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 10, string(b.ResponseName), "responsename"))
		extendedResponse.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 11, b.ResponseValue, "responsevalue"))
		packet.AppendChild(extendedResponse)
		return packet

	case *AddResponse:
		var res = lr.(*AddResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(res.MessageID), "MessageID"))
		packet2 := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddResponse, nil, "Add response")
		packet2.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(res.ResultCode), "ResultCode"))
		packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(res.MatchedDN), "MatchedDN"))
		packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, res.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(packet2)
		return packet

	case *DeleteResponse:
		var res = lr.(*DeleteResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(res.MessageID), "MessageID"))
		packet2 := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationDelResponse, nil, "Delete response")
		packet2.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(res.ResultCode), "ResultCode"))
		packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(res.MatchedDN), "MatchedDN"))
		packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, res.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(packet2)
		return packet

	case *ModifyResponse:
		var res = lr.(*ModifyResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(res.MessageID), "MessageID"))
		packet2 := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyResponse, nil, "Modify response")
		packet2.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(res.ResultCode), "ResultCode"))
		packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(res.MatchedDN), "MatchedDN"))
		packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, res.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(packet2)
		return packet

	case *CompareResponse:
		var res = lr.(*CompareResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(res.MessageID), "MessageID"))
		packet2 := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationCompareResponse, nil, "Compare response")
		packet2.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(res.ResultCode), "ResultCode"))
		packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(res.MatchedDN), "MatchedDN"))
		packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, res.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(packet2)
		return packet
	case *ldapResult:
		res := lr.(*ldapResult)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(res.MessageID), "MessageID"))
		packet2 := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Common")
		packet2.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(res.ResultCode), "ResultCode"))
		packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(res.MatchedDN), "MatchedDN"))
		packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, res.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(packet2)
		return packet

	default:
		log.Printf("newMessagePacket :: unexpected type %T", v)
	}
	return nil
}
