// Demonstrates the Cancel extended operation (RFC 3909).
//
// The server registers a slow search handler on "dc=slow,dc=example" that
// blocks for up to 30 seconds, checking for cancellation via m.Done. If
// canceled, it returns result code 118 (Canceled). A custom Cancel handler
// is also registered to log cancel requests before the built-in logic runs.
//
// Without a custom Cancel handler, the server handles Cancel automatically:
// it looks up the target operation, signals it to abort, and responds with
// an ExtendedResponse. You only need routes.Cancel(...) if you want to add
// custom logic (logging, authorization, etc.).
//
// Test with two terminal windows:
//
// Terminal 1 - start the server:
//
//	go run ./examples/cancel
//
// Terminal 2 - start a slow search, then cancel it:
//
//	# Start a slow search (will block for 30s unless canceled)
//	ldapsearch -x -H ldap://127.0.0.1:10389 -b "dc=slow,dc=example" "(objectclass=*)" &
//	SEARCH_PID=$!
//
//	# A normal search completes immediately
//	ldapsearch -x -H ldap://127.0.0.1:10389 -b "dc=example" "(objectclass=*)"
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)

	server := ldap.NewServer()
	routes := ldap.NewRouteMux()

	routes.Bind(handleBind)

	// A slow search that respects cancellation via m.Done.
	routes.Search(handleSearchSlow).
		BaseDn("dc=slow,dc=example").
		Label("Search - Slow")

	// A normal search returning sample entries.
	routes.Search(handleSearch).Label("Search - Generic")

	// Optional: register a custom Cancel handler.
	// If omitted, the server handles Cancel automatically.
	routes.Cancel(handleCancel)

	server.Handle(routes)

	go server.ListenAndServe("127.0.0.1:10389")
	log.Println("LDAP server listening on 127.0.0.1:10389")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	server.Stop()
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

// handleSearchSlow simulates a long-running search. It blocks for up to 30
// seconds, periodically checking m.Done. When a Cancel (or Abandon) signal
// arrives, the handler returns SearchResultDone with result code 118 (Canceled).
func handleSearchSlow(w ldap.ResponseWriter, m *ldap.Message) {
	log.Printf("Slow search started (messageID=%d)", m.MessageID())

	select {
	case <-m.Done:
		log.Printf("Slow search canceled (messageID=%d)", m.MessageID())
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultCanceled)
		w.Write(res)
		return
	case <-time.After(30 * time.Second):
	}

	log.Printf("Slow search completed (messageID=%d)", m.MessageID())
	e := ldap.NewSearchResultEntry("cn=result,dc=slow,dc=example")
	e.AddAttribute("cn", "result")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

// handleSearch is a generic search returning sample entries.
func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	e := ldap.NewSearchResultEntry("cn=Alice, " + string(r.BaseObject()))
	e.AddAttribute("cn", "Alice")
	e.AddAttribute("mail", "alice@example.com")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

// handleCancel is a custom Cancel handler. It logs the cancel attempt, then
// performs the standard cancel logic: look up the target message, signal it
// to abort, and respond.
//
// This is optional - if you don't register a Cancel handler, the server
// does exactly this automatically.
func handleCancel(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	log.Printf("Cancel request received (messageID=%d, requestName=%s)", m.MessageID(), r.RequestName())

	// You could add authorization checks here, e.g. only allow the same
	// bind identity to cancel their own operations.

	// Respond with NoSuchOperation - in a real implementation you would
	// parse the cancelID and look up the target. For a complete built-in
	// implementation, simply omit the routes.Cancel() registration and
	// let the server handle it automatically.
	res := ldap.NewExtendedResponse(ldap.LDAPResultNoSuchOperation)
	res.SetDiagnosticMessage("custom cancel handler - operation not found")
	w.Write(res)
}
