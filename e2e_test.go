package ldapserver

import (
	"encoding/asn1"
	"net"
	"os"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
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
	routes.Search(handleSearchSlowTest).BaseDn("dc=slow,dc=example")
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

func handleSearchSlowTest(w ResponseWriter, m *Message) {
	// Block until canceled or timeout
	select {
	case <-m.Done:
	case <-time.After(10 * time.Second):
	}
	res := NewSearchResultDoneResponse(LDAPResultCanceled)
	w.Write(res)
}

// buildCancelValue constructs a BER packet for the requestValue of a Cancel
// Extended Request (RFC 3909): SEQUENCE { cancelID INTEGER }.
// The returned packet is tagged as [CONTEXT 1] (primitive) wrapping the raw
// ASN.1 bytes, which is how goldap expects the requestValue field.
func buildCancelValue(messageID int) *ber.Packet {
	data, _ := asn1.Marshal(cancelRequestValue{CancelID: messageID})
	pkt := ber.Encode(ber.ClassContext, ber.TypePrimitive, 1, nil, "requestValue")
	pkt.Value = data
	pkt.Data.Write(data)
	return pkt
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

func TestE2E_CancelNoSuchOperation(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	conn := dialAndBind(t, addr)
	defer conn.Close()

	// Cancel a messageID that does not exist
	req := goldap.NewExtendedRequest("1.3.6.1.1.8", buildCancelValue(9999))
	_, err := conn.Extended(req)
	if err == nil {
		t.Fatal("expected error for cancel of non-existent operation")
	}
	if !goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchOperation) {
		t.Fatalf("expected NoSuchOperation (119), got: %v", err)
	}
}

func TestE2E_CancelInProgressSearch(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	// go-ldap serializes requests on a single connection, so we cannot send
	// a Cancel while a Search is blocking the read loop. Instead we use raw
	// BER packets on a plain TCP connection.
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer rawConn.Close()

	// Helper: build and send a raw LDAP message envelope.
	sendRaw := func(messageID int, appPacket *ber.Packet) {
		env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
		env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
		env.AppendChild(appPacket)
		rawConn.Write(env.Bytes())
	}

	// 1. Send a simple bind (messageID=1): [APPLICATION 0] { version=3, name="cn=test", simple="secret" }
	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "BindRequest")
	bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=test", "name"))
	bindReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "secret", "simple"))
	sendRaw(1, bindReq)

	// Read the bind response
	rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = ber.ReadPacket(rawConn)
	if err != nil {
		t.Fatalf("read bind response: %v", err)
	}

	// 2. Send a search on dc=slow,dc=example (messageID=2) - this will block server-side
	searchReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "SearchRequest")
	searchReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=slow,dc=example", "baseObject"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "scope"))       // wholeSubtree
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "derefAliases")) // neverDerefAliases
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "sizeLimit"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "timeLimit"))
	searchReq.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	// Filter: (objectclass=*) - present filter for "objectclass"
	searchReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectclass", "present"))
	// Attributes: empty sequence
	searchReq.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))
	sendRaw(2, searchReq)

	// Give the search time to register on the server
	time.Sleep(100 * time.Millisecond)

	// 3. Send Cancel extended request for messageID=2 (messageID=3)
	extReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 23, nil, "ExtendedRequest")
	extReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.1.8", "requestName"))
	extReq.AppendChild(buildCancelValue(2))
	sendRaw(3, extReq)

	// 4. Read responses. We expect:
	//    - Cancel response (messageID=3) with resultCode = Canceled (118)
	//    - Search done (messageID=2) with resultCode = Canceled (118)
	rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	gotCancelResponse := false
	gotSearchCanceled := false

	for i := 0; i < 2; i++ {
		pkt, err := ber.ReadPacket(rawConn)
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		if len(pkt.Children) < 2 {
			t.Fatalf("response %d: expected at least 2 children, got %d", i, len(pkt.Children))
		}
		msgID := pkt.Children[0].Value.(int64)
		opTag := pkt.Children[1].Tag

		switch {
		case msgID == 3 && opTag == 24: // ExtendedResponse for Cancel
			// Decode resultCode from the first child of the ExtendedResponse
			if len(pkt.Children[1].Children) < 1 {
				t.Fatalf("cancel response: no children in ExtendedResponse")
			}
			resultCode := pkt.Children[1].Children[0].Value.(int64)
			if resultCode != LDAPResultCanceled {
				t.Fatalf("cancel response: expected resultCode %d (Canceled), got %d", LDAPResultCanceled, resultCode)
			}
			gotCancelResponse = true

		case msgID == 2 && opTag == 5: // SearchResultDone
			if len(pkt.Children[1].Children) < 1 {
				t.Fatalf("search done: no children")
			}
			resultCode := pkt.Children[1].Children[0].Value.(int64)
			if resultCode != LDAPResultCanceled {
				t.Fatalf("search done: expected resultCode %d (Canceled), got %d", LDAPResultCanceled, resultCode)
			}
			gotSearchCanceled = true
		}
	}

	if !gotCancelResponse {
		t.Fatal("did not receive Cancel ExtendedResponse")
	}
	if !gotSearchCanceled {
		t.Fatal("did not receive SearchResultDone with Canceled result code")
	}
}

func TestE2E_CancelUserDefinedHandler(t *testing.T) {
	// Set up a server with a custom Cancel handler that returns a specific
	// diagnostic message, verifying it takes precedence over auto-handling.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := NewServer()
	routes := NewRouteMux()

	routes.Bind(handleBindTest)
	routes.Cancel(func(w ResponseWriter, r *Message) {
		res := NewExtendedResponse(LDAPResultNoSuchOperation)
		res.SetDiagnosticMessage("custom cancel handler")
		w.Write(res)
	})

	server.Handle(routes)
	server.Listener = ln
	go server.serve()
	defer server.Stop()

	conn := dialAndBind(t, ln.Addr().String())
	defer conn.Close()

	req := goldap.NewExtendedRequest("1.3.6.1.1.8", buildCancelValue(9999))
	_, err = conn.Extended(req)
	if err == nil {
		t.Fatal("expected error from custom cancel handler")
	}
	ldapErr, ok := err.(*goldap.Error)
	if !ok {
		t.Fatalf("expected *ldap.Error, got %T: %v", err, err)
	}
	if ldapErr.ResultCode != goldap.LDAPResultNoSuchOperation {
		t.Fatalf("expected NoSuchOperation (119), got code %d", ldapErr.ResultCode)
	}
}
