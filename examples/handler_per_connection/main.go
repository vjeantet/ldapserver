// Listen to 10389 port for LDAP Request
// and route bind request to the handleBind func

// using a handler, one can pass data from one function to another
// use the result of bind in subsequent research requests

// this example accepts all bind requests for a dn starting with 'login' and rejects others
// that is for example "loginfoo" and "loginbar" will be accepted, "foobar" will be rejected.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {

	//ldap logger
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)

	//Create a new LDAP Server
	server := ldap.NewServerWithHandlerSource(&myHandlerSource{})

	// listen on 10389
	go server.ListenAndServe("127.0.0.1:10389")

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}

// this implements interface HandlerSource. this is called by ldap server on
// each new connetion to get a handler for this connection
type myHandlerSource struct {
}

func (*myHandlerSource) GetHandler() ldap.Handler {
	routes := ldap.NewRouteMux()
	mh := &myHandler{}
	routes.Bind(mh.handleBind)
	routes.Search(mh.handleSearch).Label("Search - Generic")
	return routes
}

// the handlersource creates a new one of these for each connection
// thus data in here is unique "per connection"
type myHandler struct {
	username  string
	was_bound bool
}

// handleBind return Success if login == mysql
func (mh *myHandler) handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	mh.username = fmt.Sprintf("%s", r.Name())

	if strings.HasPrefix(mh.username, "login") {
		mh.was_bound = true
		w.Write(res)
		return
	}
	mh.was_bound = false
	log.Printf("Bind failed User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}

func (h *myHandler) handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	if !h.was_bound {
		// if no user was authenticated, then don't search.
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
		res.SetResultCode(ldap.LDAPResultInvalidCredentials)
		w.Write(res)
		return
	}
	r := m.GetSearchRequest()

	log.Printf("----- Search request by %s-------\n", h.username)
	log.Printf("Request BaseDn=%s\n", r.BaseObject())
	log.Printf("Request Filter=%s\n", r.Filter())
	log.Printf("Request FilterString=%s\n", r.FilterString())
	log.Printf("Request Attributes=%s\n", r.Attributes())
	log.Printf("Request TimeLimit=%d\n", r.TimeLimit().Int())

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		log.Print("Leaving handleSearch...")
		return
	default:
	}

	e := ldap.NewSearchResultEntry("cn=Valere JEANTET, " + string(r.BaseObject()))
	e.AddAttribute("mail", "valere.jeantet@gmail.com", "mail@vjeantet.fr")
	e.AddAttribute("company", "SODADI")
	e.AddAttribute("department", "DSI/SEC")
	e.AddAttribute("l", "Ferrieres en brie")
	e.AddAttribute("mobile", "0612324567")
	e.AddAttribute("telephoneNumber", "0612324567")
	e.AddAttribute("cn", "Valère JEANTET")
	w.Write(e)

	e = ldap.NewSearchResultEntry("cn=Claire Thomas, " + string(r.BaseObject()))
	e.AddAttribute("mail", "claire.thomas@gmail.com")
	e.AddAttribute("cn", "Claire THOMAS")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)

}
