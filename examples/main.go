package main

import (
	"log"
	"time"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {
	//Create a new LDAP Server
	server := ldap.Server{Addr: ":1389", ReadTimeout: time.Second * 2}

	//Set Search request Handler
	server.SetSearchHandler(handleSearch)

	//Set Bind request Handler
	server.SetBindHandler(handlerBind)

	//Set Unbind request Handler
	server.SetUnbindHandler(handlerUnbind)

	err := server.ListenAndServe()
	log.Printf("err = %s", err)

}

// A successfull unbind request should not send any response, but close the
// the current connexion, even if something wrong happen
func handlerUnbind(r *ldap.UnbindRequest) {
	return
}

func handlerBind(w ldap.BindResponse, r *ldap.BindRequest) {
	if string(r.GetLogin()) != "myLogin" {
		log.Print("Bind failed")
		ldap.BindError(w, ldap.LDAPResultInvalidCredentials, "login / mot de passe invalide")
		return
	}
	return
}

func handleSearch(w ldap.SearchResponse, r *ldap.SearchRequest) {
	log.Printf("Request BaseDn=%s", r.GetBaseDN())
	log.Printf("Request Filter=%s", r.GetFilter())
	log.Printf("Request Attributes=%s", r.GetAttributes())

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
