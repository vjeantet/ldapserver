// Demonstrates Serve() with a pre-existing listener and per-connection
// client data using SetData/GetData.
//
// The bind handler stores the authenticated DN in the client data.
// The search handler reads it back and returns it as an attribute,
// so each connection sees its own identity.
//
// Test with:
//
//	ldapsearch -x -H ldap://127.0.0.1:10389 -D "cn=alice" -w secret -b "dc=example" "(objectclass=*)"
package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	ldapmsg "github.com/vjeantet/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
)

func main() {
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)

	server := ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	routes.Search(handleSearch)
	server.Handle(routes)

	// Create our own listener and pass it to Serve()
	ln, err := net.Listen("tcp", "127.0.0.1:10389")
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	log.Printf("Listening on %s", ln.Addr())
	go server.Serve(ln)

	// Graceful shutdown on CTRL+C
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	server.Stop()
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	dn := string(r.Name())
	pass := string(r.AuthenticationSimple())

	if pass != "secret" {
		res := ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage("invalid credentials")
		w.Write(res)
		return
	}

	// Store the authenticated DN in the per-connection client data
	m.Client.SetData(dn)
	log.Printf("Bind success: %s", dn)

	w.Write(ldap.NewBindResponse(ldap.LDAPResultSuccess))
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	// Retrieve the DN stored during bind
	boundDN, _ := m.Client.GetData().(string)
	if boundDN == "" {
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultInsufficientAccessRights)
		res.SetDiagnosticMessage("anonymous search not allowed")
		w.Write(res)
		return
	}

	log.Printf("Search by %s on %s", boundDN, r.BaseObject())

	e := ldap.NewSearchResultEntry("cn=whoami, " + string(r.BaseObject()))
	e.AddAttribute("cn", "whoami")
	e.AddAttribute("boundDN", ldapmsg.AttributeValue(boundDN))
	e.AddAttribute("description", "This entry reflects the identity of the bound user")
	w.Write(e)

	w.Write(ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess))
}
