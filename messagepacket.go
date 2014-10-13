package ldap

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

		sr.ProtocolOp.BaseDN = msg.Packet.Children[1].Children[0].Data.Bytes()
		sr.ProtocolOp.Scope = int(msg.Packet.Children[1].Children[1].Value.(uint64))
		sr.ProtocolOp.DerefAliases = int(msg.Packet.Children[1].Children[2].Value.(uint64))
		sr.ProtocolOp.SizeLimit = int(msg.Packet.Children[1].Children[3].Value.(uint64))
		sr.ProtocolOp.TimeLimit = int(msg.Packet.Children[1].Children[4].Value.(uint64))
		sr.ProtocolOp.TypesOnly = msg.Packet.Children[1].Children[5].Value.(bool)

		var ldaperr = new(Error)
		sr.ProtocolOp.Filter, ldaperr = decompileFilter(msg.Packet.Children[1].Children[6])
		if ldaperr != nil {
			log.Printf("Error Decompiling SearchRequestFilter %s", ldaperr.Err)
		}

		for i := range msg.Packet.Children[1].Children[7].Children {
			sr.ProtocolOp.Attributes = append(sr.ProtocolOp.Attributes, msg.Packet.Children[1].Children[7].Children[i].Data.Bytes())
		}

		return sr, nil
	}

	return mm, errors.New("Unknow Ldap Operation")
}

func decompileFilter(packet *ber.Packet) (ret string, err *Error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewError(ErrorFilterDecompile, errors.New("Error decompiling filter"))
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
