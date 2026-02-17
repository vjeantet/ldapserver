package ldapserver

import (
	"sync"
	"testing"

	ldap "github.com/lor00x/goldap/message"
)

// TestConcurrentRequestListAccess exercises concurrent read/write access to
// client.requestList through GetMessageByID, registerRequest, and
// unregisterRequest. Without proper mutex protection on GetMessageByID
// (issue #28), this test fails under the race detector (-race).
func TestConcurrentRequestListAccess(t *testing.T) {
	c := &client{
		requestList: make(map[int]*Message),
	}

	const numMessages = 50
	const numReaders = 5

	// Build messages with distinct IDs.
	messages := make([]*Message, numMessages)
	for i := range messages {
		lm := ldap.NewLDAPMessageWithProtocolOp(NewBindResponse(LDAPResultSuccess))
		lm.SetMessageID(i + 1)
		messages[i] = &Message{
			LDAPMessage: lm,
			Done:        make(chan bool, 2),
			Client:      c,
		}
	}

	var wg sync.WaitGroup

	// Writers: register then unregister each message.
	for _, m := range messages {
		wg.Add(1)
		go func(m *Message) {
			defer wg.Done()
			c.registerRequest(m)
			c.unregisterRequest(m)
		}(m)
	}

	// Readers: concurrently look up message IDs while writers are active.
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := 1; id <= numMessages; id++ {
				c.GetMessageByID(id)
			}
		}()
	}

	wg.Wait()
}
