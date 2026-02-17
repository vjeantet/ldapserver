// Demonstrates referrals, search result references, and response controls.
//
// Listen on 10389 and serve three search base DNs:
//   - dc=ref,dc=example        returns a SearchResultReference pointing elsewhere
//   - dc=redirect,dc=example   returns a referral (result code 10) in SearchResultDone
//   - dc=controls,dc=example   returns a SearchResultDone with a response control
//   - (anything else)          returns two sample entries
//
// Test with ldapsearch (from openldap-clients):
//
//	ldapsearch -x -H ldap://127.0.0.1:10389 -b "dc=ref,dc=example" "(objectclass=*)"
//	ldapsearch -x -H ldap://127.0.0.1:10389 -b "dc=redirect,dc=example" "(objectclass=*)"
//	ldapsearch -x -H ldap://127.0.0.1:10389 -b "dc=controls,dc=example" "(objectclass=*)"
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)

	server := ldap.NewServer()
	routes := ldap.NewRouteMux()

	routes.Bind(handleBind)

	// A search that returns a SearchResultReference before the done message.
	routes.Search(handleSearchReference).
		BaseDn("dc=ref,dc=example").
		Label("Search - Reference")

	// A search that returns a referral inside the SearchResultDone.
	routes.Search(handleSearchReferral).
		BaseDn("dc=redirect,dc=example").
		Label("Search - Referral")

	// A search that attaches a control to the SearchResultDone.
	routes.Search(handleSearchControls).
		BaseDn("dc=controls,dc=example").
		Label("Search - Controls")

	// Catch-all search handler.
	routes.Search(handleSearch).Label("Search - Generic")

	server.Handle(routes)

	go server.ListenAndServe("127.0.0.1:10389")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	server.Stop()
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

// handleSearchReference sends a SearchResultReference (RFC 4511 sec. 4.5.3)
// followed by a successful SearchResultDone.
// The client receives the reference URL in the search result's Referrals list.
func handleSearchReference(w ldap.ResponseWriter, m *ldap.Message) {
	log.Println("Sending SearchResultReference")

	ref := ldap.NewSearchResultReference("ldap://other.example/dc=ref,dc=example")
	w.Write(ref)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

// handleSearchReferral returns SearchResultDone with result code Referral (10)
// and a referral URL list. The client receives an LDAPResultReferral error.
func handleSearchReferral(w ldap.ResponseWriter, m *ldap.Message) {
	log.Println("Sending SearchResultDone with referral")

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultReferral)
	res.SetDiagnosticMessage("please follow the referral")
	res.SetReferral(ldap.NewReferral("ldap://alt.example/dc=redirect,dc=example"))
	w.Write(res)
}

// handleSearchControls attaches a response control to the SearchResultDone
// message envelope using WriteWithControls.
func handleSearchControls(w ldap.ResponseWriter, m *ldap.Message) {
	log.Println("Sending SearchResultDone with control")

	e := ldap.NewSearchResultEntry("cn=demo,dc=controls,dc=example")
	e.AddAttribute("cn", "demo")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	ctrl := ldap.NewControl("1.2.3.4.5.6.7.8.9", false, nil)
	ldap.WriteWithControls(w, res, ctrl)
}

// handleSearch is a generic fallback returning two sample entries.
func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	e := ldap.NewSearchResultEntry("cn=Alice, " + string(r.BaseObject()))
	e.AddAttribute("cn", "Alice")
	e.AddAttribute("mail", "alice@example.com")
	w.Write(e)

	e = ldap.NewSearchResultEntry("cn=Bob, " + string(r.BaseObject()))
	e.AddAttribute("cn", "Bob")
	e.AddAttribute("mail", "bob@example.com")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
