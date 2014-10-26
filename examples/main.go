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

	//TODO: Set Add request Handler
	server.SetAddHandler(handlerAdd)

	//TODO: Set Modify request Handler
	server.SetModifyHandler(handlerModify)

	//TODO: Set Delete request Handler
	server.SetDeleteHandler(handlerDelete)

	//TODO: Set Extended request Handler
	//server.SetExtendedHandler(handlerExtended)

	go server.ListenAndServe()

	// Handle SIGINT and SIGTERM.
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}

func handlerBind(w ldap.BindResponse, r *ldap.BindRequest) {
	if string(r.GetLogin()) == "myLogin" {
		w.ResultCode = ldap.LDAPResultSuccess
		w.Send()
		return
	}

	log.Printf("Bind failed User=%s, Pass=%s", string(r.GetLogin()), string(r.GetPassword()))
	w.ResultCode = ldap.LDAPResultInvalidCredentials
	w.DiagnosticMessage = "login / mot de passe invalide"
	w.Send()
}

func handlerAdd(w ldap.AddResponse, r *ldap.AddRequest) {
	log.Printf("Adding entry: %s", r.GetEntryDN())
	//attributes values
	for _, attribute := range r.GetAttributes() {
		for _, attributeValue := range attribute.GetValues() {
			log.Printf("- %s:%s", attribute.GetDescription(), attributeValue)
		}
	}
	w.ResultCode = ldap.LDAPResultSuccess
	w.Send()
}

func handlerModify(w ldap.ModifyResponse, r *ldap.ModifyRequest) {
	log.Printf("Modify entry: %s", r.GetObject())
	log.Printf("Request : %V", w)

	for _, change := range r.GetChanges() {
		modification := change.GetModification()
		var operationString string
		switch change.GetOperation() {
		case ldap.ModifyRequestChangeOperationAdd:
			operationString = "Add"
		case ldap.ModifyRequestChangeOperationDelete:
			operationString = "Delete"
		case ldap.ModifyRequestChangeOperationReplace:
			operationString = "Replace"
		}

		log.Printf("%s attribute '%s'", operationString, modification.GetDescription())
		for _, attributeValue := range modification.GetValues() {
			log.Printf("- value: %s", attributeValue)
		}

	}

	w.ResultCode = ldap.LDAPResultSuccess
	w.Send()
}

func handlerDelete(w ldap.DeleteResponse, r *ldap.DeleteRequest) {
	log.Printf("Deleting entry: %s", r.GetEntryDN())
	w.ResultCode = ldap.LDAPResultSuccess
	w.Send()
}

func handleSearch(w ldap.SearchResponse, r *ldap.SearchRequest) {
	log.Printf("Request BaseDn=%s", r.GetBaseObject())
	log.Printf("Request Filter=%s", r.GetFilter())
	log.Printf("Request Attributes=%s", r.GetAttributes())

	//Rechercher de subschemaSubentry
	//Rercherche de NamingContext
	//Récupération des TOP noeuds

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-r.GetDoneChannel():
		log.Print("Leaving handleSearch...")
		return
	default:
	}

	e := new(ldap.SearchResultEntry)
	e.SetDn("cn=Valere JEANTET, " + string(r.GetBaseObject()))
	e.AddAttribute("mail", "valere.jeantet@gmail.com")
	e.AddAttribute("company", "SODADI")
	e.AddAttribute("department", "DSI/QSM")
	e.AddAttribute("l", "Ferrieres en brie")
	e.AddAttribute("mobile", "0612324567")
	e.AddAttribute("telephoneNumber", "0612324567")
	e.AddAttribute("cn", "Valère JEANTET")
	w.SendEntry(e)

	e = new(ldap.SearchResultEntry)
	e.SetDn("cn=Claire Thomas, " + string(r.GetBaseObject()))
	e.AddAttribute("mail", "claire.thomas@gmail.com")
	e.AddAttribute("cn", "Claire THOMAS")
	w.SendEntry(e)

	w.ResultCode = ldap.LDAPResultSuccess
	w.Send()

}
