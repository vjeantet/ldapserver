package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {
	//Create a new LDAP Server
	server := ldap.Server{Addr: ":1389"}

	//Set Search request Handler
	server.SetSearchHandler(handleSearch)

	//Set Bind request Handler
	server.SetBindHandler(handlerBind)

	//Set Unbind request Handler
	server.SetUnbindHandler(handlerUnbind)

	go server.ListenAndServe()
	//log.Printf("err = %s", err)

	// Handle SIGINT and SIGTERM.
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()

}

// A successfull unbind request should not send any response, but close the
// the current connexion, even if something wrong happen
func handlerUnbind(r *ldap.UnbindRequest) {
	return
}

func handlerBind(w ldap.BindResponse, r *ldap.BindRequest) {
	if string(r.GetLogin()) == "myLogin" {
		w.ResultCode = ldap.LDAPResultSuccess
		w.Send()
		return
	}

	log.Print("Bind failed")
	w.ResultCode = ldap.LDAPResultInvalidCredentials
	w.DiagnosticMessage = "login / mot de passe invalide"
	w.Send()
}

func handleSearch(w ldap.SearchResponse, r *ldap.SearchRequest) {
	// log.Printf("Request BaseDn=%s", r.GetBaseDN())
	// log.Printf("Request Filter=%s", r.GetFilter())
	// log.Printf("Request Attributes=%s", r.GetAttributes())

	for {
		select {
		case <-r.GetDoneSignal():
			log.Print("Leaving handleSearch...")
			return
		default:
		}

		e := new(ldap.SearchResultEntry)
		e.SetDn("cn=Valere JEANTET, " + string(r.GetBaseDN()))
		e.AddAttribute("mail", "valere.jeantet@gmail.com")
		e.AddAttribute("company", "SODADI")
		e.AddAttribute("department", "DSI/QSM")
		e.AddAttribute("l", "Ferrieres en brie")
		e.AddAttribute("mobile", "0612324567")
		e.AddAttribute("telephoneNumber", "0612324567")
		e.AddAttribute("cn", "Valère JEANTET")
		w.SendEntry(e)

		e = new(ldap.SearchResultEntry)
		e.SetDn("cn=Claire Thomas, " + string(r.GetBaseDN()))
		e.AddAttribute("mail", "claire.thomas@gmail.com")
		e.AddAttribute("cn", "Claire THOMAS")
		w.SendEntry(e)
	}
	w.ResultCode = ldap.LDAPResultSuccess
	w.Send()
}
