package ldapserver

import (
	"fmt"

	roox "github.com/vjeantet/goldap/message"
)

type Message struct {
	roox.LDAPMessage
	Client *client
	Done   chan bool
}

func (m *Message) String() string {
	return fmt.Sprintf("MessageId=%d, %s", m.MessageID(), m.ProtocolOpName())
}

// Abandon close the Done channel, to notify handler's user function to stop any
// running process
func (m *Message) Abandon() {
	m.Done <- true
}

func (m *Message) GetAbandonRequest() roox.AbandonRequest {
	return m.ProtocolOp().(roox.AbandonRequest)
}

func (m *Message) GetSearchRequest() roox.SearchRequest {
	return m.ProtocolOp().(roox.SearchRequest)
}

func (m *Message) GetBindRequest() roox.BindRequest {
	return m.ProtocolOp().(roox.BindRequest)
}

func (m *Message) GetAddRequest() roox.AddRequest {
	return m.ProtocolOp().(roox.AddRequest)
}

func (m *Message) GetDeleteRequest() roox.DelRequest {
	return m.ProtocolOp().(roox.DelRequest)
}

func (m *Message) GetModifyRequest() roox.ModifyRequest {
	return m.ProtocolOp().(roox.ModifyRequest)
}

func (m *Message) GetCompareRequest() roox.CompareRequest {
	return m.ProtocolOp().(roox.CompareRequest)
}

func (m *Message) GetExtendedRequest() roox.ExtendedRequest {
	return m.ProtocolOp().(roox.ExtendedRequest)
}
