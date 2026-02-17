package ldapserver

import (
	"net"
	"os"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
)

func TestMain(m *testing.M) {
	Logger = DiscardingLogger
	os.Exit(m.Run())
}

// startTestServer starts a fully configured LDAP server on a random port.
// It returns the address and a stop function.
func startTestServer(t *testing.T) (addr string, stop func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	server := NewServer()
	routes := NewRouteMux()

	routes.NotFound(handleNotFoundTest)
	routes.Bind(handleBindTest)
	routes.Compare(handleCompareTest)
	routes.Add(handleAddTest)
	routes.Delete(handleDeleteTest)
	routes.Modify(handleModifyTest)
	routes.Extended(handleWhoAmITest).RequestName(NoticeOfWhoAmI)
	routes.Extended(handleExtendedTest)
	routes.Search(handleSearchDSETest).
		BaseDn("").
		Scope(SearchRequestScopeBaseObject).
		Filter("(objectclass=*)")
	routes.Search(handleSearchReferenceTest).BaseDn("dc=ref,dc=example")
	routes.Search(handleSearchReferralTest).BaseDn("dc=redirect,dc=example")
	routes.Search(handleSearchControlsTest).BaseDn("dc=controls,dc=example")
	routes.Search(handleSearchTest)

	server.Handle(routes)
	server.Listener = ln
	go server.serve()

	return ln.Addr().String(), func() { server.Stop() }
}

// dialAndBind dials the server, binds with cn=test/secret, and returns the connection.
func dialAndBind(t *testing.T, addr string) *goldap.Conn {
	t.Helper()
	conn, err := goldap.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	err = conn.Bind("cn=test", "secret")
	if err != nil {
		conn.Close()
		t.Fatalf("failed to bind: %v", err)
	}
	return conn
}

// --- Handlers ---

func handleNotFoundTest(w ResponseWriter, r *Message) {
	switch r.ProtocolOpName() {
	case "BindRequest":
		res := NewBindResponse(LDAPResultSuccess)
		res.SetDiagnosticMessage("Default binding behavior set to return Success")
		w.Write(res)
	case "ExtendedRequest":
		res := NewExtendedResponse(LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	default:
		res := NewResponse(LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	}
}

func handleBindTest(w ResponseWriter, m *Message) {
	r := m.GetBindRequest()
	res := NewBindResponse(LDAPResultSuccess)
	if r.AuthenticationChoice() == "simple" {
		if string(r.Name()) == "cn=test" && string(r.AuthenticationSimple()) == "secret" {
			w.Write(res)
			return
		}
		res.SetResultCode(LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage("invalid credentials")
	} else {
		res.SetResultCode(LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
	}
	w.Write(res)
}

func handleCompareTest(w ResponseWriter, m *Message) {
	res := NewCompareResponse(LDAPResultCompareTrue)
	w.Write(res)
}

func handleAddTest(w ResponseWriter, m *Message) {
	res := NewAddResponse(LDAPResultSuccess)
	w.Write(res)
}

func handleDeleteTest(w ResponseWriter, m *Message) {
	res := NewDeleteResponse(LDAPResultSuccess)
	w.Write(res)
}

func handleModifyTest(w ResponseWriter, m *Message) {
	res := NewModifyResponse(LDAPResultSuccess)
	w.Write(res)
}

func handleWhoAmITest(w ResponseWriter, m *Message) {
	res := NewExtendedResponse(LDAPResultSuccess)
	w.Write(res)
}

func handleExtendedTest(w ResponseWriter, m *Message) {
	res := NewExtendedResponse(LDAPResultSuccess)
	w.Write(res)
}

func handleSearchDSETest(w ResponseWriter, m *Message) {
	e := NewSearchResultEntry("")
	e.AddAttribute("vendorName", "Valere JEANTET")
	e.AddAttribute("vendorVersion", "0.0.1")
	e.AddAttribute("objectClass", "top", "extensibleObject")
	e.AddAttribute("supportedLDAPVersion", "3")
	e.AddAttribute("namingContexts", "o=My Company, c=US")
	w.Write(e)

	res := NewSearchResultDoneResponse(LDAPResultSuccess)
	w.Write(res)
}

func handleSearchTest(w ResponseWriter, m *Message) {
	r := m.GetSearchRequest()

	select {
	case <-m.Done:
		return
	default:
	}

	e := NewSearchResultEntry("cn=Valere JEANTET, " + string(r.BaseObject()))
	e.AddAttribute("mail", "valere.jeantet@gmail.com", "mail@vjeantet.fr")
	e.AddAttribute("company", "SODADI")
	e.AddAttribute("department", "DSI/SEC")
	e.AddAttribute("l", "Ferrieres en brie")
	e.AddAttribute("mobile", "0612324567")
	e.AddAttribute("telephoneNumber", "0612324567")
	e.AddAttribute("cn", "Valere JEANTET")
	w.Write(e)

	e = NewSearchResultEntry("cn=Claire Thomas, " + string(r.BaseObject()))
	e.AddAttribute("mail", "claire.thomas@gmail.com")
	e.AddAttribute("cn", "Claire THOMAS")
	w.Write(e)

	res := NewSearchResultDoneResponse(LDAPResultSuccess)
	w.Write(res)
}

func handleSearchReferenceTest(w ResponseWriter, m *Message) {
	ref := NewSearchResultReference("ldap://other.example/dc=ref,dc=example")
	w.Write(ref)

	res := NewSearchResultDoneResponse(LDAPResultSuccess)
	w.Write(res)
}

func handleSearchReferralTest(w ResponseWriter, m *Message) {
	res := NewSearchResultDoneResponse(LDAPResultReferral)
	res.SetReferral(NewReferral("ldap://alt.example/dc=redirect,dc=example"))
	w.Write(res)
}

func handleSearchControlsTest(w ResponseWriter, m *Message) {
	res := NewSearchResultDoneResponse(LDAPResultSuccess)
	WriteWithControls(w, res, NewControl("1.2.3.4.5.6.7.8.9", false, nil))
}

// --- Tests ---

func TestE2E_BindSuccess(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn, err := goldap.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = conn.Bind("cn=test", "secret")
	if err != nil {
		t.Fatalf("expected bind success, got: %v", err)
	}
}

func TestE2E_BindFailure(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn, err := goldap.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = conn.Bind("cn=wrong", "bad")
	if err == nil {
		t.Fatal("expected bind failure, got nil error")
	}
	ldapErr, ok := err.(*goldap.Error)
	if !ok {
		t.Fatalf("expected *ldap.Error, got %T", err)
	}
	if ldapErr.ResultCode != goldap.LDAPResultInvalidCredentials {
		t.Fatalf("expected result code %d, got %d", goldap.LDAPResultInvalidCredentials, ldapErr.ResultCode)
	}
}

func TestE2E_SearchDSE(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	req := goldap.NewSearchRequest(
		"",
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectclass=*)",
		[]string{},
		nil,
	)

	sr, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	if len(sr.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(sr.Entries))
	}

	vendorName := sr.Entries[0].GetAttributeValue("vendorName")
	if vendorName == "" {
		t.Fatal("expected vendorName attribute to be present")
	}
}

func TestE2E_SearchGeneric(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	req := goldap.NewSearchRequest(
		"o=My Company, c=US",
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectclass=*)",
		[]string{},
		nil,
	)

	sr, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	if len(sr.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(sr.Entries))
	}

	for _, entry := range sr.Entries {
		if entry.GetAttributeValue("cn") == "" {
			t.Errorf("expected cn attribute on entry %s", entry.DN)
		}
		if entry.GetAttributeValue("mail") == "" {
			t.Errorf("expected mail attribute on entry %s", entry.DN)
		}
	}
}

func TestE2E_SearchRouteConstraints(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	// DSE search: BaseDN="" + ScopeBaseObject → DSE handler (1 entry with vendorName)
	dseReq := goldap.NewSearchRequest(
		"",
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectclass=*)",
		[]string{},
		nil,
	)
	sr, err := conn.Search(dseReq)
	if err != nil {
		t.Fatalf("DSE search: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Fatalf("DSE: expected 1 entry, got %d", len(sr.Entries))
	}
	if sr.Entries[0].GetAttributeValue("vendorName") == "" {
		t.Fatal("DSE: expected vendorName attribute")
	}

	// Generic search: BaseDN="o=My Company, c=US" + ScopeWholeSubtree → Generic handler (2 entries)
	genReq := goldap.NewSearchRequest(
		"o=My Company, c=US",
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectclass=*)",
		[]string{},
		nil,
	)
	sr, err = conn.Search(genReq)
	if err != nil {
		t.Fatalf("Generic search: %v", err)
	}
	if len(sr.Entries) != 2 {
		t.Fatalf("Generic: expected 2 entries, got %d", len(sr.Entries))
	}
	// Verify these are from the generic handler (have mail attribute), not DSE
	for _, entry := range sr.Entries {
		if entry.GetAttributeValue("mail") == "" {
			t.Errorf("Generic: expected mail attribute on entry %s", entry.DN)
		}
	}
}

func TestE2E_Add(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	addReq := goldap.NewAddRequest("cn=John Jones, o=My Company, c=US", nil)
	addReq.Attribute("cn", []string{"John Jones"})
	addReq.Attribute("sn", []string{"Jones"})
	addReq.Attribute("objectclass", []string{"inetOrgPerson"})

	err := conn.Add(addReq)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
}

func TestE2E_Modify(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	modReq := goldap.NewModifyRequest("cn=myNetCard,ou=Networks,dc=example,dc=com", nil)
	modReq.Replace("objectclass", []string{"device", "top"})
	modReq.Add("macAddress", []string{"00:11:22:33:44:55"})

	err := conn.Modify(modReq)
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
}

func TestE2E_Delete(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	delReq := goldap.NewDelRequest("cn=John Jones, o=My Company, c=US", nil)

	err := conn.Del(delReq)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestE2E_Compare(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	ok, err := conn.Compare(
		"cn=Matti Meikku, ou=My Unit, o=My Company, c=FI",
		"password",
		"secretpassword",
	)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !ok {
		t.Fatal("expected compare to return true")
	}
}

func TestE2E_ExtendedWhoAmI(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	result, err := conn.WhoAmI(nil)
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	// WhoAmI returns *WhoAmIResult, just check no error and non-nil result
	if result == nil {
		t.Fatal("expected non-nil WhoAmI result")
	}
}

func TestE2E_UnbindClosesConnection(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)

	// Close sends an unbind request and closes the connection
	conn.Close()

	// A search after close should fail
	req := goldap.NewSearchRequest(
		"",
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectclass=*)",
		[]string{},
		nil,
	)
	_, err := conn.Search(req)
	if err == nil {
		t.Fatal("expected error after unbind, got nil")
	}
}

func TestE2E_NotFoundHandler(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	// Send an Extended request with an unknown OID — should hit NotFound handler
	req := goldap.NewExtendedRequest("1.2.3.4.5.6.7.8.9", nil)
	_, err := conn.Extended(req)
	if err == nil {
		t.Fatal("expected error for unrouted extended request")
	}
	if !goldap.IsErrorWithCode(err, goldap.LDAPResultUnwillingToPerform) {
		t.Fatalf("expected LDAPResultUnwillingToPerform, got: %v", err)
	}
}

func TestE2E_FullSequence(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	// 1. Add
	addReq := goldap.NewAddRequest("cn=John Jones, o=My Company, c=US", nil)
	addReq.Attribute("cn", []string{"John Jones"})
	addReq.Attribute("sn", []string{"Jones"})
	addReq.Attribute("objectclass", []string{"inetOrgPerson"})
	if err := conn.Add(addReq); err != nil {
		t.Fatalf("add: %v", err)
	}

	// 2. Modify
	modReq := goldap.NewModifyRequest("cn=John Jones, o=My Company, c=US", nil)
	modReq.Replace("sn", []string{"Smith"})
	if err := conn.Modify(modReq); err != nil {
		t.Fatalf("modify: %v", err)
	}

	// 3. Delete
	delReq := goldap.NewDelRequest("cn=John Jones, o=My Company, c=US", nil)
	if err := conn.Del(delReq); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// 4. Compare
	ok, err := conn.Compare(
		"cn=Matti Meikku, ou=My Unit, o=My Company, c=FI",
		"password",
		"secretpassword",
	)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !ok {
		t.Fatal("expected compare true")
	}

	// 5. Search
	searchReq := goldap.NewSearchRequest(
		"o=My Company, c=US",
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectclass=*)",
		[]string{},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(sr.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(sr.Entries))
	}
}

func TestE2E_SearchResultReference(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	req := goldap.NewSearchRequest(
		"dc=ref,dc=example",
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectclass=*)",
		[]string{},
		nil,
	)

	sr, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(sr.Referrals) == 0 {
		t.Fatal("expected at least one referral in search result")
	}
	found := false
	for _, ref := range sr.Referrals {
		if ref == "ldap://other.example/dc=ref,dc=example" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected referral URL not found, got: %v", sr.Referrals)
	}
}

func TestE2E_LDAPResultReferral(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	req := goldap.NewSearchRequest(
		"dc=redirect,dc=example",
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectclass=*)",
		[]string{},
		nil,
	)

	_, err := conn.Search(req)
	if err == nil {
		t.Fatal("expected error for referral result code")
	}
	if !goldap.IsErrorWithCode(err, goldap.LDAPResultReferral) {
		t.Fatalf("expected LDAPResultReferral, got: %v", err)
	}
}

func TestE2E_ResponseControls(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	req := goldap.NewSearchRequest(
		"dc=controls,dc=example",
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectclass=*)",
		[]string{},
		nil,
	)

	sr, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(sr.Controls) == 0 {
		t.Fatal("expected at least one control in search result")
	}
	found := false
	for _, ctrl := range sr.Controls {
		if ctrl.GetControlType() == "1.2.3.4.5.6.7.8.9" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected control OID 1.2.3.4.5.6.7.8.9 not found, got: %v", sr.Controls)
	}
}
