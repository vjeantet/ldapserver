[![GoDoc](https://godoc.org/github.com/vjeantet/ldapserver?status.svg)](https://godoc.org/github.com/vjeantet/ldapserver)


**ldapserver** is a helper library for building server software capable of speaking the LDAP protocol. This could be an alternate implementation of LDAP, a custom LDAP proxy or even a completely different backend capable of "masquerading" its API as a LDAP Server.

The package supports
* All basic LDAP Operations (bind, search, add, compare, modify, delete, extended)
* Cancel extended operation (RFC 3909) with built-in handling
* SSL
* StartTLS
* Serve with a pre-existing `net.Listener` (`Serve()` and `ServeTLS()`)
* Per-connection client data (`SetData` / `GetData`)
* Unbind request is implemented, but is handled internally to close the connection.
* Graceful stopping
* Basic request routing inspired by [net/http ServeMux](http://golang.org/pkg/net/http/#ServeMux)
* Referrals and SearchResultReference messages
* Response controls on outgoing messages
* Logger customisation (log interface)

# Default behaviors
## Abandon request
If you don't set a route to handle AbandonRequest, the package will handle it for you. (signal sent to message.Done chan)

## Cancel request (RFC 3909)
The Cancel extended operation (OID `1.3.6.1.1.8`) is handled automatically by the server. When a client sends a Cancel request, the server:
1. Decodes the target messageID from the request value
2. Looks up the in-progress operation on the same connection
3. Returns `NoSuchOperation` (119) if the target is not found
4. Returns `CannotCancel` (121) for non-cancelable operations (Bind, Abandon, StartTLS, Cancel)
5. Otherwise signals the target via `m.Done` and responds with `Canceled` (118)

Handlers should check `m.Done` to detect both Cancel and Abandon signals:

```Go
select {
case <-m.Done:
    // Operation was canceled or abandoned
    res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultCanceled)
    w.Write(res)
    return
default:
}
```

To override the built-in behavior (e.g. for logging or authorization), register a custom handler with `routes.Cancel(handler)`.

See the `examples/cancel` directory for a complete working example.

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

// handleBind return Success if username == "myLogin" , whatever the value of the password
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

# Serve and ServeTLS

Instead of `ListenAndServe`, you can pass your own `net.Listener` to integrate the LDAP server into an existing application:

```Go
ln, _ := net.Listen("tcp", ":10389")
go server.Serve(ln)
```

For LDAPS, set `TLSConfig` on the server and use `ServeTLS`:

```Go
server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
ln, _ := net.Listen("tcp", ":10636")
go server.ServeTLS(ln)
```

# Per-connection client data

Handlers can store and retrieve arbitrary data on the current connection using `SetData` and `GetData`. This is useful for tracking session state (e.g. the authenticated DN after a bind):

```Go
// In the bind handler: store the authenticated identity
func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
    r := m.GetBindRequest()
    m.Client.SetData(string(r.Name()))
    w.Write(ldap.NewBindResponse(ldap.LDAPResultSuccess))
}

// In the search handler: retrieve it
func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
    boundDN, _ := m.Client.GetData().(string)
    log.Printf("Search by %s", boundDN)
    // ...
}
```

Each connection has its own independent data. `GetData` returns `nil` until `SetData` is called.

See the `examples/client_data` directory for a complete working example.

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
- `TestParseCancelRequestValue*` — Cancel request value ASN.1 decoding (valid IDs, nil, invalid, trailing data, zero)

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
| `TestE2E_CancelNoSuchOperation` | Cancel a non-existent messageID returns `NoSuchOperation` (119) |
| `TestE2E_CancelInProgressSearch` | Cancel a blocking search; both cancel response and search result return `Canceled` (118) |
| `TestE2E_ClientData` | `SetData`/`GetData` persists across operations on the same connection; two connections have isolated data |
| `TestE2E_ClientDataNilByDefault` | `GetData` returns `nil` on a fresh connection |
| `TestE2E_CancelUserDefinedHandler` | Custom `routes.Cancel(handler)` takes precedence over built-in auto-handling |
