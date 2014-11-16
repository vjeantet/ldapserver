package main

import (
	"crypto/tls"
	"log"
	"os"
	"os/signal"
	"syscall"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {
	//Create a new LDAP Server
	server := ldap.NewServer()

	//Set Search request Handler
	server.SetSearchHandler(handleSearch)

	//Set Bind request Handler
	server.SetBindHandler(handleBind)

	//Set Add request Handler
	server.SetAddHandler(handleAdd)

	//Set Modify request Handler
	server.SetModifyHandler(handleModify)

	//Set Delete request Handler
	server.SetDeleteHandler(handleDelete)

	//Set Extended request Handler
	server.SetExtendedHandler(handleExtended)

	//Set Compare request Handler
	server.SetCompareHandler(handleCompare)

	// listen on 10389
	//go server.ListenAndServe(":10389")

	tlsConfiguration := func(s *ldap.Server) {
		config, _ := getTLSconfig()
		s.TLSconfig = config
	}

	//listen on port 10389, with TLS support (StartTLS)
	go server.ListenAndServe(":10389", tlsConfiguration)

	// LDAPS SSL
	// secureConn := func(s *ldap.Server) {
	// 	s.Listener = tls.NewListener(s.Listener, s.TLSconfig)
	// }
	// go server.ListenAndServe(":636", tlsConfiguration, secureConn)

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}

// getTLSconfig returns a tls configuration used
// to build a TLSlistener for TLS or StartTLS
func getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionSSL30,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "127.0.0.1",
	}, nil
}

func handleBind(w ldap.BindResponse, r *ldap.BindRequest) {
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

// The resultCode is set to compareTrue, compareFalse, or an appropriate
// error.  compareTrue indicates that the assertion value in the ava
// Comparerequest field matches a value of the attribute or subtype according to the
// attribute's EQUALITY matching rule.  compareFalse indicates that the
// assertion value in the ava field and the values of the attribute or
// subtype did not match.  Other result codes indicate either that the
// result of the comparison was Undefined, or that
// some error occurred.
func handleCompare(w ldap.CompareResponse, r *ldap.CompareRequest) {
	log.Printf("Comparing entry: %s", r.GetEntry())
	//attributes values
	log.Printf(" attribute name to compare : \"%s\"", r.GetAttributeValueAssertion().GetName())
	log.Printf(" attribute value expected : \"%s\"", r.GetAttributeValueAssertion().GetValue())

	w.ResultCode = ldap.LDAPResultCompareTrue
	//w.ResultCode = ldap.LDAPResultCompareFalse
	w.Send()
}

func handleAdd(w ldap.AddResponse, r *ldap.AddRequest) {
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

func handleModify(w ldap.ModifyResponse, r *ldap.ModifyRequest) {
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

func handleDelete(w ldap.DeleteResponse, r *ldap.DeleteRequest) {
	log.Printf("Deleting entry: %s", r.GetEntryDN())
	w.ResultCode = ldap.LDAPResultSuccess
	w.Send()
}

func handleExtended(w ldap.ExtendedResponse, r *ldap.ExtendedRequest) {
	log.Printf("Extended request received, name=%s", r.GetResponseName())
	log.Printf("Extended request received, value=%x", r.GetResponseValue())
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
	e.AddAttribute("mail", "valere.jeantet@gmail.com", "mail@vjeantet.fr")
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

// localhostCert is a PEM-encoded TLS cert with SAN DNS names
// "127.0.0.1" and "[::1]", expiring at the last second of 2049 (the end
// of ASN.1 time).
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBOTCB5qADAgECAgEAMAsGCSqGSIb3DQEBBTAAMB4XDTcwMDEwMTAwMDAwMFoX
DTQ5MTIzMTIzNTk1OVowADBaMAsGCSqGSIb3DQEBAQNLADBIAkEAsuA5mAFMj6Q7
qoBzcvKzIq4kzuT5epSp2AkcQfyBHm7K13Ws7u+0b5Vb9gqTf5cAiIKcrtrXVqkL
8i1UQF6AzwIDAQABo08wTTAOBgNVHQ8BAf8EBAMCACQwDQYDVR0OBAYEBAECAwQw
DwYDVR0jBAgwBoAEAQIDBDAbBgNVHREEFDASggkxMjcuMC4wLjGCBVs6OjFdMAsG
CSqGSIb3DQEBBQNBAJH30zjLWRztrWpOCgJL8RQWLaKzhK79pVhAx6q/3NrF16C7
+l1BRZstTwIGdoGId8BRpErK1TXkniFb95ZMynM=
-----END CERTIFICATE-----
`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPQIBAAJBALLgOZgBTI+kO6qAc3LysyKuJM7k+XqUqdgJHEH8gR5uytd1rO7v
tG+VW/YKk3+XAIiCnK7a11apC/ItVEBegM8CAwEAAQJBAI5sxq7naeR9ahyqRkJi
SIv2iMxLuPEHaezf5CYOPWjSjBPyVhyRevkhtqEjF/WkgL7C2nWpYHsUcBDBQVF0
3KECIQDtEGB2ulnkZAahl3WuJziXGLB+p8Wgx7wzSM6bHu1c6QIhAMEp++CaS+SJ
/TrU0zwY/fW4SvQeb49BPZUF3oqR8Xz3AiEA1rAJHBzBgdOQKdE3ksMUPcnvNJSN
poCcELmz2clVXtkCIQCLytuLV38XHToTipR4yMl6O+6arzAjZ56uq7m7ZRV0TwIh
AM65XAOw8Dsg9Kq78aYXiOEDc5DL0sbFUu/SlmRcCg93
-----END RSA PRIVATE KEY-----
`)
