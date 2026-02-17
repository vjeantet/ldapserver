[![GoDoc](https://godoc.org/github.com/vjeantet/ldapserver?status.svg)](https://godoc.org/github.com/vjeantet/ldapserver)
[![Build Status](https://travis-ci.org/vjeantet/ldapserver.svg)](https://travis-ci.org/vjeantet/ldapserver)

**This package is a work in progress.**

**ldapserver** is a helper library for building server software capable of speaking the LDAP protocol. This could be an alternate implementation of LDAP, a custom LDAP proxy or even a completely different backend capable of "masquerading" its API as a LDAP Server.

The package supports
* All basic LDAP Operations (bind, search, add, compare, modify, delete, extended)
* SSL
* StartTLS
* Unbind request is implemented, but is handled internally to close the connection.
* Graceful stopping
* Basic request routing inspired by [net/http ServeMux](http://golang.org/pkg/net/http/#ServeMux)
* Referrals and SearchResultReference messages
* Response controls on outgoing messages
* Logger customisation (log interface)

# Default behaviors
## Abandon request
If you don't set a route to handle AbandonRequest, the package will handle it for you. (signal sent to message.Done chan)

## No Route Found
When no route matches the request, the server will first try to call a special *NotFound* route, if nothing is specified, it will return an *UnwillingToResponse* Error code (53)

Feel free to contribute, comment :)

#  Sample Code
```Go
// Listen to 10389 port for LDAP Request
// and route bind request to the handleBind func
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {
	//ldap logger
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)

	//Create a new LDAP Server
	server := ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	server.Handle(routes)

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

// handleBind return Success if login == mysql
func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if string(r.Name()) == "myLogin" {
		w.Write(res)
		return
	}

	log.Printf("Bind failed User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}
```

# Referrals, References and Controls

## SearchResultReference

Send a `SearchResultReference` to redirect the client to another server for part of the search:

```Go
ref := ldap.NewSearchResultReference("ldap://other.example/dc=ref,dc=example")
w.Write(ref)

res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
w.Write(res)
```

## Referral in LDAPResult

Return a referral result code (10) with one or more referral URLs:

```Go
res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultReferral)
res.SetDiagnosticMessage("please follow the referral")
res.SetReferral(ldap.NewReferral("ldap://alt.example/dc=redirect,dc=example"))
w.Write(res)
```

## Response Controls

Attach controls to the LDAPMessage envelope using `WriteWithControls`:

```Go
res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
ctrl := ldap.NewControl("1.2.3.4.5.6.7.8.9", false, nil)
ldap.WriteWithControls(w, res, ctrl)
```

`WriteWithControls` accepts one or more controls as variadic arguments. It is backward-compatible - the `ResponseWriter` interface is unchanged.

See the `examples/referrals_controls` directory for a complete working example.

# More examples
Look into the "examples" folder.

# Tests

```bash
go test -v              # run all tests
go test -race -v        # run all tests with the race detector
go test -v -run TestE2E # run only the E2E tests
```

## Unit tests

- `TestConcurrentRequestListAccess` — verifies thread-safe access to the per-connection request map
- `TestShutdownListenerRace` — checks for races during server shutdown
- `TestValidBindRequest`, `TestValidBindAfterInvalidConnection` — raw protocol-level bind scenarios
- `TestInvalidFirstByte_NoServerCrash`, `TestGarbageBytes_NoServerCrash` — server resilience to malformed input
- `TestStopRefusesNewConnections` — confirms the listener is closed before `Stop()` returns

## End-to-end tests (`e2e_test.go`)

These tests start a full LDAP server (random port, all operations routed) and exercise it with a real LDAP client (`github.com/go-ldap/ldap/v3`).

| Test | What it covers |
|------|---------------|
| `TestE2E_BindSuccess` | Successful simple bind |
| `TestE2E_BindFailure` | Bind with wrong credentials returns `InvalidCredentials` (49) |
| `TestE2E_SearchDSE` | Root DSE search (BaseDN="", ScopeBaseObject) returns 1 entry with `vendorName` |
| `TestE2E_SearchGeneric` | Subtree search returns 2 entries with expected attributes |
| `TestE2E_SearchRouteConstraints` | Route matching by BaseDN/Scope/Filter directs requests to the correct handler |
| `TestE2E_Add` | Add entry returns Success |
| `TestE2E_Modify` | Modify entry (replace + add attributes) returns Success |
| `TestE2E_Delete` | Delete entry returns Success |
| `TestE2E_Compare` | Compare returns `CompareTrue` (6) |
| `TestE2E_ExtendedWhoAmI` | Extended WhoAmI operation returns Success |
| `TestE2E_UnbindClosesConnection` | After unbind/close, further operations fail |
| `TestE2E_NotFoundHandler` | Unrouted Extended request triggers NotFound handler (`UnwillingToPerform`, 53) |
| `TestE2E_FullSequence` | Bind, Add, Modify, Delete, Compare, Search on a single connection |
| `TestE2E_SearchResultReference` | Handler sends a `SearchResultReference`; client receives the referral URL |
| `TestE2E_LDAPResultReferral` | Handler returns `SearchResultDone` with result code `Referral` (10) |
| `TestE2E_ResponseControls` | Handler attaches a control via `WriteWithControls`; client sees the control OID |
