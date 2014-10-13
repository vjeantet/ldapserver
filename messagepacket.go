package ldapserver

import (
	"bufio"
	"errors"
	"log"

	"github.com/vjeantet/asn1-ber"
)

type messagePacket struct {
	Packet *ber.Packet
}

func (msg *messagePacket) getOperation() int {
	return int(msg.Packet.Children[1].Tag)
}

func (msg *messagePacket) getMessageId() int {
	return int(msg.Packet.Children[0].Value.(uint64))
}

func (msg *messagePacket) getRequestMessage() (LDAPRequest, error) {
	var mm Message
	mm.MessageId = int(msg.Packet.Children[0].Value.(uint64))

	if msg.getOperation() == ApplicationUnbindRequest {
		var ur UnbindRequest
		ur.Message = mm
		return ur, nil
	}

	if msg.getOperation() == ApplicationBindRequest {
		var br BindRequest
		br.Message = mm
		br.SetLogin(msg.Packet.Children[1].Children[1].Data.Bytes())
		br.SetPassword(msg.Packet.Children[1].Children[2].Data.Bytes())
		br.SetVersion(int(msg.Packet.Children[1].Children[0].Value.(uint64)))
		return br, nil
	}

	if msg.getOperation() == ApplicationSearchRequest {
		var sr SearchRequest
		sr.Message = mm
		sr.ProtocolOp.BaseDN = msg.Packet.Children[1].Children[0].Data.Bytes()
		sr.ProtocolOp.Scope = int(msg.Packet.Children[1].Children[1].Value.(uint64))
		sr.ProtocolOp.DerefAliases = int(msg.Packet.Children[1].Children[2].Value.(uint64))
		sr.ProtocolOp.SizeLimit = int(msg.Packet.Children[1].Children[3].Value.(uint64))
		sr.ProtocolOp.TimeLimit = int(msg.Packet.Children[1].Children[4].Value.(uint64))
		sr.ProtocolOp.TypesOnly = msg.Packet.Children[1].Children[5].Value.(bool)

		var ldaperr error
		sr.ProtocolOp.Filter, ldaperr = decompileFilter(msg.Packet.Children[1].Children[6])
		if ldaperr != nil {
			log.Printf("Error Decompiling SearchRequestFilter %s", ldaperr)
		}

		for i := range msg.Packet.Children[1].Children[7].Children {
			sr.ProtocolOp.Attributes = append(sr.ProtocolOp.Attributes, msg.Packet.Children[1].Children[7].Children[i].Data.Bytes())
		}

		return sr, nil
	}

	return mm, errors.New("Unknow Ldap Operation")
}

func decompileFilter(packet *ber.Packet) (ret string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("Error decompiling filter")
		}
	}()
	ret = "("
	err = nil
	child_str := ""

	switch packet.Tag {
	case FilterAnd:
		ret += "&"
		for _, child := range packet.Children {
			child_str, err = decompileFilter(child)
			if err != nil {
				return
			}
			ret += child_str
		}
	case FilterOr:
		ret += "|"
		for _, child := range packet.Children {
			child_str, err = decompileFilter(child)
			if err != nil {
				return
			}
			ret += child_str
		}
	case FilterNot:
		ret += "!"
		child_str, err = decompileFilter(packet.Children[0])
		if err != nil {
			return
		}
		ret += child_str

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
	message_packet := &messagePacket{Packet: p}
	return message_packet, err
}

func NewMessagePacket(lr LDAPResponse) *ber.Packet {
	switch v := lr.(type) {
	case BindResponse:
		var b = lr.(BindResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(b.Request.GetMessageId()), "MessageID"))
		bindResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
		bindResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(b.ResultCode), "ResultCode"))
		bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, b.MatchedDN, "MatchedDN"))
		bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, b.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(bindResponse)
		return packet

	case SearchResponse:
		var res = lr.(SearchResponse)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(res.Request.GetMessageId()), "MessageID"))
		searchResultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultDone, nil, "Search done")
		searchResultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(res.ResultCode), "ResultCode"))
		searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, res.MatchedDN, "MatchedDN"))
		searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, res.DiagnosticMessage, "DiagnosticMessage"))
		packet.AppendChild(searchResultDone)
		return packet

	case SearchResultEntry:
		var s = lr.(SearchResultEntry)
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(s.request.GetMessageId()), "MessageID"))
		searchResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "SearchResultEntry")
		searchResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, s.DN, "LDAPDN"))
		attributes_list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes List")
		for j := range s.Attributes {
			attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
			attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, s.Attributes[j].Name, "type"))
			values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
			for k := range s.Attributes[j].Values {
				values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, s.Attributes[j].Values[k], "val"))
			}
			attributes.AppendChild(values)
			attributes_list.AppendChild(attributes)

		}
		searchResponse.AppendChild(attributes_list)
		packet.AppendChild(searchResponse)
		return packet

	default:
		log.Fatalf("unexpected type %T", v)
	}
	return nil
}
