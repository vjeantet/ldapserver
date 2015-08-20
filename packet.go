package ldapserver

import (
	"bufio"
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

func (msg *messagePacket) readMessage() (m roox.LDAPMessage, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid packet received hex=%x, %#v", msg.bytes, r)
		}
	}()

	return decodeMessage(msg.bytes)
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
