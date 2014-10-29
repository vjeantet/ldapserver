package ldapserver

import "fmt"

type protocolOp interface {
	String() string
}

type message struct {
	wroteMessage int
	messageID    int
	protocolOp   protocolOp
	Controls     []interface{}
	out          chan response
	Done         chan bool
}

func (m message) getMessageID() int {
	return m.messageID
}

func (m message) String() string {
	return fmt.Sprintf("MessageId=%d, %s", m.messageID, m.protocolOp.String())
}

func (m message) getProtocolOp() protocolOp {
	return m.protocolOp
}

// abort close the Done channel, to notify handler's user function to stop any
// running process
func (m message) abort() {
	close(m.Done)
}

//GetDoneChannel return a channel, which indicate the the request should be
//aborted quickly, because the client abandonned the request, the server qui quitting, ...
func (m *message) GetDoneChannel() chan bool {
	return m.Done
}
