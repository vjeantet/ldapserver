package main

import (
	"log"
	"time"

	"github.com/vjeantet/ldapserver"
)

func main() {
	//Create a new LDAP Server
	server := ldap.Server{Addr: ":1389", ReadTimeout: time.Second * 2}

	//Set Search request Handler
	server.OnSearchRequest = handleSearch

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
		ldap.BindError(w, "login / mot de passe invalide", ldap.LDAPResultInvalidCredentials)
		return
	}
	return
}

func handleSearch(w *ldap.SearchResponse, r *ldap.SearchRequest) *ldap.Error {
	log.Printf("Request BaseDn=%s", r.GetBaseDN())
	log.Printf("Request Filter=%s", r.GetFilter())
	log.Printf("Request Attributes=%s", r.GetAttributes())

	e := new(ldap.Entry)

	e.SetDn("cn=Valere JEANTET, " + string(r.GetBaseDN()))
	e.AddAttribute("mail", "valere.jeantet@gmail.com")
	e.AddAttribute("company", "SODADI")
	e.AddAttribute("department", "DSI/QSM")
	e.AddAttribute("l", "Ferrieres en brie")
	e.AddAttribute("mobile", "0664323585")
	e.AddAttribute("telephoneNumber", "0664323585")
	e.AddAttribute("cn", "Valère JEANTET")
	w.AddEntry(e)

	e = new(ldap.Entry)
	e.SetDn("cn=Claire Vidalie, " + string(r.GetBaseDN()))
	e.AddAttribute("mail", "claire.jeantet@gmail.com")
	e.AddAttribute("cn", "Claire JEANTET")
	w.AddEntry(e)

	return ldap.NewError(ldap.LDAPResultSuccess, nil)
}
