package ldapserver

import (
	"bufio"
	"errors"
	"log"

	ber "github.com/vjeantet/asn1-ber"
)

type messagePacket struct {
	Packet *ber.Packet
}

func (msg *messagePacket) getOperation() int {
	return int(msg.Packet.Children[1].Tag)
}

func (msg *messagePacket) getMessageID() int {
	return int(msg.Packet.Children[0].Value.(uint64))
}

func (msg *messagePacket) getRequestMessage() (request, error) {
	var mm message
	mm.messageID = int(msg.Packet.Children[0].Value.(uint64))

	if msg.getOperation() == ApplicationUnbindRequest {
		var ur UnbindRequest
		ur.message = mm
		return ur, nil
	}

	if msg.getOperation() == ApplicationBindRequest {
		var br BindRequest
		br.message = mm
		br.SetLogin(msg.Packet.Children[1].Children[1].Data.Bytes())
		br.SetPassword(msg.Packet.Children[1].Children[2].Data.Bytes())
		br.SetVersion(int(msg.Packet.Children[1].Children[0].Value.(uint64)))
		return br, nil
	}

	if msg.getOperation() == ApplicationSearchRequest {
		var sr SearchRequest
		sr.message = mm
		sr.protocolOp.BaseObject = msg.Packet.Children[1].Children[0].Data.Bytes()
		sr.protocolOp.Scope = int(msg.Packet.Children[1].Children[1].Value.(uint64))
		sr.protocolOp.DerefAliases = int(msg.Packet.Children[1].Children[2].Value.(uint64))
		sr.protocolOp.SizeLimit = int(msg.Packet.Children[1].Children[3].Value.(uint64))
		sr.protocolOp.TimeLimit = int(msg.Packet.Children[1].Children[4].Value.(uint64))
		sr.protocolOp.TypesOnly = msg.Packet.Children[1].Children[5].Value.(bool)

		var ldaperr error
		sr.protocolOp.Filter, ldaperr = decompileFilter(msg.Packet.Children[1].Children[6])
		if ldaperr != nil {
			log.Printf("error decompiling searchrequestfilter %s", ldaperr)
		}

		for i := range msg.Packet.Children[1].Children[7].Children {
			sr.protocolOp.Attributes = append(sr.protocolOp.Attributes, msg.Packet.Children[1].Children[7].Children[i].Data.Bytes())
		}

		return sr, nil
	}

	if msg.getOperation() == ApplicationAbandonRequest {
		var r AbandonRequest
		r.message = mm
		r.setIDToAbandon(int(msg.Packet.Children[1].Value.(uint64)))
		return r, nil
	}

	return mm, errors.New("unknow ldap operation")
}

func decompileFilter(packet *ber.Packet) (ret string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("error decompiling filter")
		}
	}()
	ret = "("
	err = nil
	childStr := ""

	switch packet.Tag {
	case FilterAnd:
		ret += "&"
		for _, child := range packet.Children {
			childStr, err = decompileFilter(child)
			if err != nil {
				return
			}
			ret += childStr
		}
	case FilterOr:
		ret += "|"
		for _, child := range packet.Children {
			childStr, err = decompileFilter(child)
			if err != nil {
				return
			}
			ret += childStr
		}
	case FilterNot:
		ret += "!"
		childStr, err = decompileFilter(packet.Children[0])
		if err != nil {
			return
		}
		ret += childStr

	case FilterSubstrings:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "="
		switch packet.Children[1].Children[0].Tag {
		case FilterSubstringsInitial:
			ret += ber.DecodeString(packet.Children[1].Children[0].Data.Bytes()) + "*"
		case FilterSubstringsAny:
			ret += "*" + ber.DecodeString(packet.Children[1].Children[0].Data.Bytes()) + "*"
		case FilterSubstringsFinal:
			ret += "*" + ber.DecodeString(packet.Children[1].Children[0].Data.Bytes())
		}
	case FilterEqualityMatch:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	case FilterGreaterOrEqual:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += ">="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	case FilterLessOrEqual:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "<="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	case FilterPresent:
		if 0 == len(packet.Children) {
			ret += ber.DecodeString(packet.Data.Bytes())
		} else {
			ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		}
		ret += "=*"
	case FilterApproxMatch:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "~="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	}

	ret += ")"
	return
}

func readMessagePacket(br *bufio.Reader) (*messagePacket, error) {
	p, err := ber.ReadPacket(br)
	//ber.PrintPacket(p)
	messagePacket := &messagePacket{Packet: p}
	return messagePacket, err
}

func newMessagePacket(lr response) *ber.Packet {
	switch v := lr.(type) {
	case BindResponse:
		var b = lr.(BindResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(b.request.getMessageID()), "MessageID"))
		bindResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
		bindResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(b.ResultCode), "ResultCode"))
		bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(b.MatchedDN), "MatchedDN"))
		bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, b.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(bindResponse)
		return packet

	case SearchResponse:
		var res = lr.(SearchResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(res.request.getMessageID()), "MessageID"))
		searchResultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultDone, nil, "Search done")
		searchResultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(res.ResultCode), "ResultCode"))
		searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(res.MatchedDN), "MatchedDN"))
		searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, res.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(searchResultDone)
		return packet

	case SearchResultEntry:
		var s = lr.(SearchResultEntry)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(s.request.getMessageID()), "MessageID"))
		searchResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "SearchResultEntry")
		searchResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, s.dN, "LDAPDN"))
		attributesList := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes List")
		for j := range s.attributes {
			attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
			attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, s.attributes[j].Name, "type"))
			values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
			for k := range s.attributes[j].Values {
				values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, s.attributes[j].Values[k], "val"))
			}
			attributes.AppendChild(values)
			attributesList.AppendChild(attributes)

		}
		searchResponse.AppendChild(attributesList)
		packet.AppendChild(searchResponse)
		return packet

	case ExtendedResponse:
		var b = lr.(ExtendedResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, 0, "MessageID"))
		extendedResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedResponse, nil, "Extended Response")
		extendedResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(b.ResultCode), "ResultCode"))
		extendedResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(b.MatchedDN), "MatchedDN"))
		extendedResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, b.DiagnosticMessage, "DiagnosticMessage"))
		extendedResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, string(b.responseName), "responsename"))
		extendedResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, b.responseValue, "responsevalue"))
		packet.AppendChild(extendedResponse)
		return packet

	default:
		log.Printf("newMessagePacket :: unexpected type %T", v)
	}
	return nil
}
