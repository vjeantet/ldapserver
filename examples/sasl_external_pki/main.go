/*
This "examples/sasl_external_pki" demo demonstrates SASL/EXTERNAL
via Mutual TLS Authentication. Using a SASL mechanism such as this
is *far more preferable* than to use the *deprecated* SIMPLE BIND
facility in real-world production environments.

Additional features:

  - Improved *tls.Config initialization, security
  - Revocation, expiration checks for peer certificates
  - Proper issuer (CA) chain
  - Updated listener cert/key pair
  - OpenLDAP-style "authz-regex" modifier of authz DNs
  - RootDSE TLS-conditional listing of "EXTERNAL" as a "supportedSASLMechanism"
  - Changed "My Company" context to "Acme" to mirror demo PKI structure

See the "examples/sasl_external_pki/pki" directory for usable client
test certificates. One is valid, one is expired and one is revoked.

IMPORTANT: Just so I say it out loud: the PKI content included in this
demo is intended for this demo ONLY and should NEVER be used in any real
production environment.

See the "examples/sasl_external_pki/README.md" file for instructions
on utilizing these user certificates for testing (hint: ~/.ldaprc or
personal env vars).

The handlers for "Add", "Modify", "Compare" and "Delete" have been
removed as they are not relevant to this demo.

The hard-coded RootDSE "supportedSASLMechanisms" "NTLM", "DIGEST-MD5",
"SIMPLE" "CRAM-MD5", "GSSAPI" and "GSS-SPNEGO" are commented out, as
they are not relevant to this demo.
*/
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {
	//Create a new LDAP Server
	server := ldap.NewServer()

	// build our authz policy store
	buildAuthzPolicies()

	// Create routes bindings
	routes := ldap.NewRouteMux()
	routes.NotFound(handleNotFound)
	routes.Abandon(handleAbandon)
	routes.Bind(handleBind)

	routes.Extended(handleStartTLS).
		RequestName(ldap.NoticeOfStartTLS).Label("StartTLS")

	routes.Extended(handleWhoAmI).
		RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")

	routes.Extended(handleExtended).Label("Ext - Generic")

	routes.Search(handleSearchDSE).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)").
		Label("Search - ROOT DSE")

	routes.Search(handleSearchAcme).
		BaseDn("o=Acme").
		Scope(ldap.SearchRequestScopeBaseObject).
		Label("Search - Acme Root")

	routes.Search(handleSearch).Label("Search - Generic")

	//Attach routes to server
	server.Handle(routes)

	// listen on 10389 and serve
	go server.ListenAndServe("127.0.0.1:10389")

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}

/*
buildAuthzPolicies adds the specified regex and target
authorization identity to the AuthzRegexPolicies var.
Users may customize as needed.
*/
func buildAuthzPolicies() {
	// Add an explicit (non-regex) targeted match
	// policy, just for the sake of example ...
	authzRegex.Push(
		`cn=admin`,
		`cn=rootDN`,
	)

        // Add users certificate policy.
        authzRegex.Push(
                `(?i)^CN=([^,]+),OU=Users,O=The Acme Widgets Corporation,ST=California,C=US$`,
                `cn=$1,ou=People,o=Acme`,
	)

	// Add servers certificate policy. This
	// is useful in cases where LDAP servers
	// bind to other LDAP servers for things
	// like chaining or content replication.
        authzRegex.Push(
        	`(?i)^CN=([^,]+),OU=Systems,O=The Acme Widgets Corporation,ST=California,C=US$`,
        	`cn=$1,ou=Servers,o=Acme`,
	)
}

func handleNotFound(w ldap.ResponseWriter, r *ldap.Message) {
	switch r.ProtocolOpType() {
	case ldap.ApplicationBindRequest:
		res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
		res.SetDiagnosticMessage("Default binding behavior set to return Success")

		w.Write(res)

	default:
		res := ldap.NewResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	}
}

func handleAbandon(w ldap.ResponseWriter, m *ldap.Message) {
	var req = m.GetAbandonRequest()
	// retrieve the request to abandon, and send a abort signal to it
	if requestToAbandon, ok := m.Client.GetMessageByID(int(req)); ok {
		requestToAbandon.Abandon()
		log.Printf("Abandon signal sent to request processor [messageID=%d]", int(req))
	}
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	req := m.GetBindRequest()
	user := string(req.Name())

	// obtain the connection from the message payload
	// if -- and only if -- it is a *tls.Conn instance,
	// meaning STARTTLS was initialized in the request.
	if assert, ok := m.Client.GetConn().(*tls.Conn); ok {
		// grab the TLS client cert from state ...
		cert := assert.ConnectionState().PeerCertificates[0]
		// ... and extract the subject DN
		user = cert.Subject.String()
	}

	// Authorization regular expressions.
	//
	// If we match an authz policy, overwrite user with
	// the authz DN. If not, we will use the *original*
	// Subject DN *as-is*. 
	if user != "" {
		if dn, ok := authzRegex.Apply(user); ok {
			user = dn
		}
	} else {
		user = "anonymous"
	}

	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	var diag string

	switch choice := req.AuthenticationChoice(); choice {
	case "simple":
		switch strings.ToLower(user) {
		case "cn=rootdn":
			log.Printf("Bind: User=%q [ADMIN], Pass=***, Auth=%q", user, choice)
		case "anonymous":
			log.Printf("Bind: User=%q, Auth=%q", user, choice)
		default:
			// any other simple dn
			log.Printf("Bind: User=%q, Pass=***, Auth=%q", user, choice)
		}
	case "sasl":
		// we know the request is SASL, but we want to know the
		// specific *MECHANISM* of SASL in use for this request.
		mech := string(req.AuthenticationSasl().Mechanism())
		switch strings.ToUpper(mech) {
		case "EXTERNAL":
			// SASL/EXTERNAL normally implies client
			// certs or hardware crypto devices.
			diag = "dn:" + user
			log.Printf("Bind: User=%q, Auth=%q, Mechanism=%q", user, choice, mech)

		case "GSSAPI", "SIMPLE", "GSS-SPNEGO", "NTLM":
			// TODO - moar mechanisms. We could import a go sasl
			// package, or we could roll our own mech handlers.
			// EXTERNAL was easy enough, given much of the work
			// was already done, but others could be sufficiently
			// complex that a 3rd party import *might* be advisable.
			diag = "SASL mechanism not yet implemented: " + mech
			res.SetResultCode(ldap.LDAPResultAuthMethodNotSupported)

		default:
			// other SASL mechanisms are not implemented. I am
			// leaning towards only doing non-obsolete mechanism
			// implementations, which would rule out things like
			// DIGEST-MD5 and CRAM-MD5.
			diag = "SASL mechanism not supported: " + mech
			res.SetResultCode(ldap.LDAPResultAuthMethodNotSupported)
		}
	default:
		log.Printf("Bind failed User=%q, Auth=%q", user, choice)
		diag = "auth facility not recognized: " + choice
		res.SetResultCode(ldap.LDAPResultAuthMethodNotSupported)
	}

	res.SetDiagnosticMessage(diag)
	w.Write(res)

	return
}

func handleExtended(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	log.Printf("Extended request received, name=%s", r.RequestName())
	log.Printf("Extended request received, value=%x", r.RequestValue())
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleWhoAmI(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleSearchDSE(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

	e := ldap.NewSearchResultEntry("")
	e.AddAttribute("vendorName", "Valère JEANTET")
	e.AddAttribute("vendorVersion", "0.0.1")
	e.AddAttribute("objectClass", "top", "extensibleObject")
	e.AddAttribute("supportedLDAPVersion", "3")
	e.AddAttribute("namingContexts", "o=Acme")
	// e.AddAttribute("subschemaSubentry", "cn=schema")
	// e.AddAttribute("namingContexts", "ou=system", "ou=schema", "dc=example,dc=com", "ou=config")
	e.AddAttribute("supportedFeatures", "1.3.6.1.4.1.4203.1.5.1")
	e.AddAttribute("supportedControl", "2.16.840.1.113730.3.4.3", "1.3.6.1.4.1.4203.1.10.1", "2.16.840.1.113730.3.4.2", "1.3.6.1.4.1.4203.1.9.1.4", "1.3.6.1.4.1.42.2.27.8.5.1", "1.3.6.1.4.1.4203.1.9.1.1", "1.3.6.1.4.1.4203.1.9.1.3", "1.3.6.1.4.1.4203.1.9.1.2", "1.3.6.1.4.1.18060.0.0.1", "2.16.840.1.113730.3.4.7", "1.2.840.113556.1.4.319")
	e.AddAttribute("supportedExtension", "1.3.6.1.4.1.1466.20036", "1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.18060.0.1.5", "1.3.6.1.4.1.18060.0.1.3", "1.3.6.1.4.1.1466.20037")

	////////////////////////////////////////////////////////////////////
	// TODO - only disclose the StartTLS OID (1.3.6.1.4.1.1466.20037)
	// as a supportedExtension if the LDAP server actually supports TLS
	// (i.e.: it has a cert/key loaded as well as a TLS listener). I am
	// not currently sure how to do this, given that we don't have access
	// to the listener from handlers.
	////////////////////////////////////////////////////////////////////

	// Add other SASL mechanisms as we implement them, but DO
	// NOT list the EXTERNAL mechanism explicitly (see below
	// for verification). I'm AGAINST adding deprecated or
	// obsolete mechanisms -- namely DIGEST-MD5, CRAM-MD5 --
	// but that's just me.
	//e.AddAttribute("supportedSASLMechanisms",
	//	"NTLM", "GSSAPI", "GSS-SPNEGO", "CRAM-MD5",
	//	"SIMPLE", "DIGEST-MD5")

	// Verify the current request is actually TLS.
	if _, isTLS := m.Client.GetConn().(*tls.Conn); isTLS {
		// EXTERNAL should only be listed as a supported
		// mechanism IF, and ONLY IF, a TLS handshake
		// has already taken place (successfully!) for
		// the session. OpenLDAP does this correctly.
		//
		// While other LDAP vendors DO list it implicitly,
		// making it conditional serves as a nice trouble
		// shooting helper to let the user know they are
		// indeed binding via SASL/EXTERNAL (and, thus,
		// are connected securely).
		e.AddAttribute("supportedSASLMechanisms", "EXTERNAL")
	}
	// e.AddAttribute("entryUUID", "f290425c-8272-4e62-8a67-92b06f38dbf5")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleSearchAcme(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("handleSearchAcme - Request BaseDn=%s", r.BaseObject())

	e := ldap.NewSearchResultEntry(string(r.BaseObject()))
	e.AddAttribute("objectClass", "top", "organizationalUnit")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

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

/*
crl contains the up-to-date copy of the certificate revocation
list. In the future, this should probably be stored in an object,
perhaps Server, instead of in a global var.

In real-life production environments, this should be updated
regularly (and without the need to restart the LDAP server).
*/
var crl *x509.RevocationList

/*
getTLSconfig returns a tls configuration used
to build a TLS listener for TLS or StartTLS.
*/
func getTLSconfig() (*tls.Config, error) {
	// parse listener certificate and key
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		return &tls.Config{}, err
	}

	// read users CRL into global crl var
	if crl, err = parseCRL(usersCRL); err != nil {
		return &tls.Config{}, err
	}

	// parse issuer bundle
	bundle := x509.NewCertPool()
	if !bundle.AppendCertsFromPEM(bundledCAs) {
		err = fmt.Errorf("no certs found in bundle, or bundle is malformed")
		return &tls.Config{}, err
	}

	return &tls.Config{
		// Here we allow, but don't require, client certs.
		// Changing this to tls.RequireAndVerifyClientCert
		// will basically prohibit SIMPLE BINDs altogether,
		// which may, or may not, be what you want.
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      bundle,
		ServerName:   "127.0.0.1",

		// Examine the PEER (client) certificate, and verify
		// that is (a) has not expired, and (b) is not revoked.
    		VerifyPeerCertificate: func(raw [][]byte, issuers [][]*x509.Certificate) (err error) {
			var cert *x509.Certificate
			if cert, err = x509.ParseCertificate(raw[0]); err == nil {
        			if isRevoked(cert) {
            				err = fmt.Errorf("peer certificate is revoked")
				} else if isExpired(cert) {
            				err = fmt.Errorf("peer certificate has expired")
				}
			}
        		return
    		},
	}, nil
}

func handleStartTLS(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)

	tlsconfig, err := getTLSconfig()
	if err != nil {
		res.SetDiagnosticMessage("StartTLS error: " + err.Error())
		// See RFC2830, section 2.3
		res.SetResultCode(ldap.LDAPResultUnavailable)
		w.Write(res)
		return
	}

	tlsConn := tls.Server(m.Client.GetConn(), tlsconfig)
	res.SetResponseName(ldap.NoticeOfStartTLS)
	w.Write(res)

	if err = tlsConn.Handshake(); err != nil {
		log.Printf("StartTLS handshake error: %v", err)
		tlsConn.Close()
		return
	}

	m.Client.SetConn(tlsConn)
	log.Println("StartTLS OK")
}

func isRevoked(cert *x509.Certificate) (is bool) {
    for _, rc := range crl.RevokedCertificates {
        if cert.SerialNumber.Cmp(rc.SerialNumber) == 0 {
		is = true
		break
        }
    }
    return
}

func isExpired(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotAfter)
}

/*
parseCRL returns an instance of *x509.RevocationList alongside
an error following an attempt to read and process the input
pemBytes argument.
*/
func parseCRL(pemBytes []byte) (*x509.RevocationList, error) {
    block, _ := pem.Decode(pemBytes)
    if block == nil {
        return nil, fmt.Errorf("no PEM block found")
    }
    if block.Type != "X509 CRL" {
        return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
    }

    return x509.ParseRevocationList(block.Bytes)
}

/*
Define a policy store which "converts" an X.509
subject DN to a proper LDAP DN if a match is made.
In the future, we may consider making this a
"Server" struct field value instead of a global var.
*/
var authzRegex AuthzRegexPolicies

/*
AuthzRegexPolicies contains all runtime pattern matchers.
Policies are called in the order in which they reside
within instances of this type.
*/
type AuthzRegexPolicies []AuthzRegexPolicy

/*
AuthzRegexPolicy implements a single pattern matcher.
*/
type AuthzRegexPolicy struct {
    Pattern *regexp.Regexp
    Replace string
}

/*
apply returns a string DN alongside a success-indicative
Boolean value following an attempt to "convert" a subject
DN to an LDAP DN using a policy found within the receiver.
*/
func (r AuthzRegexPolicy) apply(subj string) (string, bool) {
    m := r.Pattern.FindStringSubmatch(subj)
    if m == nil {
        return "", false
    }

    // Replace $1, $2, et al., with captured groups.
    out := r.Replace
    for i := 1; i < len(m); i++ {
        out = strings.ReplaceAll(out, fmt.Sprintf("$%d", i), m[i])
    }
    return out, true
}

/*
Apply returns a processed authz-regex string alongside a success-indicative
Boolean value following an attempt to process the subj input value against
any number of [AuthzRegexPolicy] instances defined within the receiver instance.

If no match was made, the original input value is used as-is.
*/
func (r AuthzRegexPolicies) Apply(subj string) (out string, ok bool) {
	var _out string
	var idx int = -1
	for i := 0; i < len(r) && !ok; i++ {
		log.Printf("authz-regex: trying policy %d", i)
		if _out, ok = r[i].apply(subj); ok {
			idx = i
		}
	}

	if ok {
		log.Printf("authz-regex: policy %d matched", idx)
		out = _out
	} else {
		// use original
		log.Printf("authz-regex: no policy match")
		out = subj
	}

	return
}

/*
Push initializes and appends a new instance of [AuthzRegexPolicy],
bearing the regex pattern and the target syntax, to the receiver
instance.
*/
func (r *AuthzRegexPolicies) Push(pat, val string) {
	*r = append(*r, AuthzRegexPolicy{
		Pattern: regexp.MustCompile(pat),
	    	Replace: val,
	})
}

//////////////////////////////////
/// BEGIN EMBEDDED PKI OBJECTS ///
//////////////////////////////////

/*
localhostCert is a PEM-encoded TLS cert with a SAN DNS name
of "localhost" and SAN IPAddresses "127.0.0.1" and "[::1]",
expiring in 2036. It is signed by the "Systems" CA included
in the provided issuer-bundle.pem file / bundledCAs var.
*/
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIFCTCCAvGgAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVT
MRMwEQYDVQQIDApDYWxpZm9ybmlhMSUwIwYDVQQKDBxUaGUgQWNtZSBXaWRnZXRz
IENvcnBvcmF0aW9uMRAwDgYDVQQLDAdJc3N1ZXJzMS8wLQYDVQQDDCZTeXN0ZW1z
IEludGVybWVkaWF0ZSBJc3N1aW5nIEF1dGhvcml0eTAeFw0yNjA3MTEwMDUzMzVa
Fw0zNjA3MDgwMDUzMzVaMG8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9y
bmlhMSUwIwYDVQQKDBxUaGUgQWNtZSBXaWRnZXRzIENvcnBvcmF0aW9uMRAwDgYD
VQQLDAdTeXN0ZW1zMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCvaa4zsNJnKw4ZU1hDUela0W0ugU27x7ktekbUZ/6v
XGSeqtYBhtklkOY4RFO+kIX47DZkk2AnxApelfYyU6MkJnHx5f7Za+5NxhNf2kR/
CRZpOBDVG0iGKcmhKPrHPL390XZyhJOtBAwexIhjKOr0fFQBeLIWooyeJC8wltrp
HOn8LZNKwn/oZiFsxA7YlaoYyTVskOk/OLUAoqb9R5zZ7zpsvLk/K3hquhhsOi17
rbGUbrbrST9kGStYD3OxtdXphlOua8P9BHuN7urZLBnvCYJ6FO4uV6FjaRlkwnVV
rMFPGjxDA2wPx5cJmCDvKrUquO+8xtZ86cxF3j1LNZ+zAgMBAAGjgZAwgY0wLAYD
VR0RBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU2Zw2Y4WSlBMTNh8u
6wzE/HWE344wHwYDVR0jBBgwFoAU+YFQzd1WTAFYXZ0tFjw4huzw46gwDQYJKoZI
hvcNAQELBQADggIBAFfVt/zPUIp5k3pUsGb7MRJLTuGMGH2skZYzeAyO5m9Z4gd7
kRxOHGWNTRJqIX4M7bsD1MCLZ5LA2zcAc5dPfn66qd6098LctC19mr1BtzkUhdS2
d4T41c4lLHt6G0JRMZhb2aQmsVKlJQRYTCQPvVmwLeQ4unhxMyd/oqWYiEOqPMH5
rRzeec7YumZ4yzgMhyceMH7WDEeutglugDTPdBP4SsDCDd4VFPr2Xjzud178HeWQ
8J/Ibyxl7FzP0WBvYK5Y5pJOqWuEmylw4ick1artEuoYvgyrO2hPdzy9FOj2MDML
4TkJ2fESjuUcKBm3JQSFFwefF0PAy0CED5wRlZXj5g3WqF6J9m7qsHUCp0vCXoYn
KqFOPqZikwNJf1qSeBY16EzAYSh3e1hx32Ov/ZQvyePgXvDNG2N/5SEU02DcMBtr
2YTNjIjDZCyqDSFKPhEAxJCykl6cGqKhl0WKJ17+yhJscPAtsqzhTSLxwX1W4mHl
0si4tCl9t1pD/AYG3HIX0JnsoLzq6kR0MmY592RYIYlH66o3IUsU/DRbVrikd/1x
uh3wyvG+iZpo1LoVCpZc6pubSDo/BQSycB78Nqy3r50syz6dIouYe8TNVycCUEUb
9Haqw+E3h7FzWLoEe9Hy3deoE4+Ff5B+HgFzSW/5jUbCW9Qa1Kzly4jZpTFD
-----END CERTIFICATE-----
`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCvaa4zsNJnKw4Z
U1hDUela0W0ugU27x7ktekbUZ/6vXGSeqtYBhtklkOY4RFO+kIX47DZkk2AnxApe
lfYyU6MkJnHx5f7Za+5NxhNf2kR/CRZpOBDVG0iGKcmhKPrHPL390XZyhJOtBAwe
xIhjKOr0fFQBeLIWooyeJC8wltrpHOn8LZNKwn/oZiFsxA7YlaoYyTVskOk/OLUA
oqb9R5zZ7zpsvLk/K3hquhhsOi17rbGUbrbrST9kGStYD3OxtdXphlOua8P9BHuN
7urZLBnvCYJ6FO4uV6FjaRlkwnVVrMFPGjxDA2wPx5cJmCDvKrUquO+8xtZ86cxF
3j1LNZ+zAgMBAAECggEAAXYAs0HYlsRh3dh3Bo8tlt83U2j/ST5CGWddz1ITFHR8
CrhDMl25pu7x2UEfGMS3tkQytca7yR5VtHD3onariAG2oZGipulCYa0cfIgNrv3X
4nDK7xjG6LB7aJdgnf0wWzyoiblMnjxyOhAKpMIdUYOhktDlsXuRbpXAO4gzcuKS
Zow4zuYToKxTu1g/mM80YVKiuspFCdtxO6+IThaA4iMA6F0E9b4xmdMJZzOdPjev
yS3V7ZC1QQaSBOBZQWdo1ilJo4YVmae9H4KPiRs3epy4C5Ty647RxV86LFtwo1zI
ECFIrio+GmfByeEuO+k44ESUzZwSXbWhgkT4vGyy5QKBgQDXcKDYOegpWh4zjjPJ
ZAA0xZtwpE3cVfuy8OlAc51Mu+bp+I6uni/Vzz3x5LLZ4c3BLhcduGkq+jA8hagI
4E/LTYGtJwByjNN823avut2nqPVamh5Q2zswLQo1xxsohxDz7pw5pC5uji17I0OV
AgGH4A6BXxO5xucjbKOh0Q7C3QKBgQDQb+Yk7UMmIX4Q4t8/kNE+/D+lALMROp7A
9zYVL8in1YuxmdAWnzDw2FAxDGft08CDkydRkLDzeTwpKP94YP5vLao5zsKS1KJx
QLou7I0s3NmcwE7df1HpREkPHaO03PN2pupIms2sTG9qoQJ+wFAgUgiXFIPU+iyc
i3YDLS/bzwKBgQCvLiv75oo7JcYtEdJWTfRE9PHCFDgjk98I0BA6kkgz3w6S7cPH
hWVMLCooiVhNBukxzfKJ/iu2AJ48eEn8fbkkjS+GxpH8kzpc6m+F0SLvc9meBHfm
M33bXKRSukYBHGLSlxF9ZV1EFGQzHqeTgIASJkRlOhRmGbBVA7/CkqW4GQKBgF3K
nHLtWJPl6kZK8E44Kg//jdv/rpQIHruSAgISmGX9T3jBT8N+KpWVoLARdwqriCss
ojqvsxA783hJ/Hr8mkEI+Vo90Ywkplvz1lObGgOf9UP1vQcqbX9bvMxSeAHAksVH
YpD9J6NqWZBPl0HV47hHcZoaHyBM2pounxHa2Xg9AoGBAMsIToxjLU4l+whODIKW
en7GWJ3fB36Rv0PCqTPLVZj5t6RZ4gSyFn8+2pMDanUciDEUoDZFQByZACIm1Cna
eOUrXrcnyFwS4ccZDwA/CTEcQFs+iePy5xg5XQh2bFyXOCxppR3uimpiGJ+Fxim/
dmyyBILsmRu5FiFO4tjUFl9e
-----END PRIVATE KEY-----
`)

/*
bundledCAs contains three (3) issuing certificates: one (1) root
and two (2) intermediates:

  - root issuer
      |__ systems issuer
      |__ users issuer

All CAs expire in 2036.
*/
var bundledCAs []byte = []byte(`-----BEGIN CERTIFICATE-----
MIIF6zCCA9OgAwIBAgICEAQwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExJTAjBgNVBAoMHFRoZSBBY21lIFdpZGdldHMg
Q29ycG9yYXRpb24xEDAOBgNVBAsMB0lzc3VlcnMxHzAdBgNVBAMMFlJvb3QgSXNz
dWluZyBBdXRob3JpdHkwHhcNMjYwNzExMDAxNjUzWhcNMzYwNzA4MDAxNjUzWjCB
jDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExJTAjBgNVBAoMHFRo
ZSBBY21lIFdpZGdldHMgQ29ycG9yYXRpb24xEDAOBgNVBAsMB0lzc3VlcnMxLzAt
BgNVBAMMJlN5c3RlbXMgSW50ZXJtZWRpYXRlIElzc3VpbmcgQXV0aG9yaXR5MIIC
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqK1Qj7fRSyKHi2n0zlhfGF1k
P+2lLM3lbg4j7vxtQSXfXsYvnz1nOl5Bx4dzyEuK3Ec/5Qy1RrUbR8BYbuAy8yJi
RQthzjbmt7MA41ew87Iip87q+wenLl+rF1J5ojrKrsc2+lwB8bssvwFKQV5Yv1lx
37liPhWtikO3TsjwBDrgSb5nIulfJPWI1gwbWDrQv9sk73Se6PYEJqPeo2qNO5W8
boGstCGutfY2oPmFzyXyn6/MljhdImHy/Q47JnHYN1xDYo9gNiqMzY5SPZJkiELD
R2tpUhlH3wMK2qlmGRaP68tHZ4ke8PxkstzVCafvknyu9VZrHacKFix+q4qQEhMx
7YkSjQ2cQeh3miC8pepc8N9GXJfS/uHQrzTAToxXeAxLFFlbyWcMNt3a4gOE7epR
cdA1/Mu3OYb2bjdI1w5xf+8YUxzwiV4XNqPTtKvA6Q3OCMkrGivKCXI227dnKqMM
0LQF1FHLzPA3llxCXbarEEplwx8vwqOTOVB+4DewKwlf/RwmYdUGECehzd0iCxD7
go9X0HaOsiu0HZ5+ZmXBuyu4Kc9lp1hCY+oKXcTdNueaD40Xh2UXg1F3zeCrE3XF
QaCpBk9D/sczcIiC2mQhC4+z8p4SH13k0g+WjmDSWgUotZ1e4TBFy/lOx3s5YGm8
5KYxxr901js0/v7CrOsCAwEAAaNmMGQwHQYDVR0OBBYEFPmBUM3dVkwBWF2dLRY8
OIbs8OOoMB8GA1UdIwQYMBaAFFio3/zOiqpRT6Jn5vMoC7/n3HhWMBIGA1UdEwEB
/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAW
+SD1MSoZlqIsmhGHkrT/5qoJO40pdgzO+y8jwgX4voM2zWyL7eNKLAhel+vQ0ywF
HVLGCvlGKU+uf5/ZEr4Gsbgtrm676KSsxwgfw1C8tpLd7bDn8EFGctPE/qroStg9
zudeRMZv8CuUpbrCCQPaIu9s3myXTcLXXjS4SH7qJyTfdODOU5K6kilh8E2lr84o
RvI5G4NajMicL1C94OhH59dNzJ6vorArKRKb94fPkLoQnKQ5ta/yBN3Sbx2w0e6d
5N4EEUiiGq59xKJhhuAZVm8FLhDw+CfDhQtvOcfFTwKyhSRH+0hJS/FNv81xBErN
Sjmon/IBzNpONFS4jRxoOBKuFveaFGQvgX8gbasCaKuW22Es3NmCGkOLw/Jyiwgy
DHf64eafY3+Ydx0d++uehj83cgrOeMmxOGdsvRVBancJn1wluXT1J9lcLPMVUpwk
bcWXg48LVS01IwltM74HKF/X+clgzbgeXHkuEbq+7pjemJE1Hyv1wxAo+6JUsFeq
72CabkISag2B8OPGCP4+xPAl6owq+kKMG16hgTLVr3oCMhoUGQPYtgUvrURazwsP
mulPBy4gysz99VcGNwyT3aSPWzP8siQb5GeddIsUij1e51lVdWKhycsWmM6U8nxz
UOmlzjGPpJ2GurHGqW0LOs6MveSEdpc3hkTps7ZcFA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF6TCCA9GgAwIBAgICEAMwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExJTAjBgNVBAoMHFRoZSBBY21lIFdpZGdldHMg
Q29ycG9yYXRpb24xEDAOBgNVBAsMB0lzc3VlcnMxHzAdBgNVBAMMFlJvb3QgSXNz
dWluZyBBdXRob3JpdHkwHhcNMjYwNzExMDAxNTQ3WhcNMzYwNzA4MDAxNTQ3WjCB
ijELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExJTAjBgNVBAoMHFRo
ZSBBY21lIFdpZGdldHMgQ29ycG9yYXRpb24xEDAOBgNVBAsMB0lzc3VlcnMxLTAr
BgNVBAMMJFVzZXJzIEludGVybWVkaWF0ZSBJc3N1aW5nIEF1dGhvcml0eTCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJq+3vxjtcMKD/TW1w7dPWn9FXYB
wJYQcMEnLlHjjS3KDrRxAWhxtuX8FwyCPM3cpCDqkb1VmAzFUGLgPiId91WA7hER
WPHA8DRrmLbE1Swpjf1eYZq9OlWW3EUFf7g1DWvkkU5RLcjxTnYeqzvLJaMCmk/n
SGrF8XIxHudB3Bklxg2aj4kmdR+STHO4E6TBk72xtJLMGo9eeRFjKtlwLoNesz1v
WCG6MGk7XGAuJgRZtritw2kZZru1o6lxjTRjCTD2AZaceN1KmNHNNCKKBaUo4hnk
bf5rE5N63luHWM3geIV2HMyyXVa/yvZavaefRwWllxm17hUtBLTFoV1AEoasK3F1
cng7LHBXFdTOdaa4wxpOrdxF2HfxfvSWCMHv6/cK1P5MzNv7tIUXhlIK6DaAPeFn
lMpn55vG3WWJHVzf83Me5szCMTnU+JFePQ9iLVcmtyVtVA7xLRnFU5FkeL03+tSb
hahJwq1EZZIzpplrftIgMLK4hDvOm8F0CQLl2T4cBqAHFcWkrdkdNgzwaxP/aZ6b
SLoTUFkUW2rGTWFf1y5si2EGkIiDeN4DPP1+YEbHBQ9h3OcjGjnqLUap97IpnDjA
l3iMeNrQfrqFRGU9L2xbK7y7VYFxqifDFWcF6WIvC2hmYGI4w408yuGeR+cD8hVO
DpLbv2B74pA/RfxfAgMBAAGjZjBkMB0GA1UdDgQWBBQ6u4ILdIaizEGmUQGRJVDL
yuWfdDAfBgNVHSMEGDAWgBRYqN/8zoqqUU+iZ+bzKAu/59x4VjASBgNVHRMBAf8E
CDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAHVGt
OVfY6FevULNGeRWm53G/1IFM03PirT6o+9C1SEFXdcecyncUkdP1JKmk/TF3bvIh
UPyFy6s4bPRExyCglcQ81M0ZeJLiInUrMoBnF9Dy4kEzwnyAnshPZe1ZUMRDuXcf
+dbF+ZWZcE3QR+WXvOfz1QVMR2kF3GMfpoiJ/pXYOZBopWpfYHVHJjvAz4sNLi75
VpHDTlJGHl/Uj+eV4C30xkwFCnpk24W+x23nZIa9E+W8Z/jwILMxxjhPfxJ5hvOu
6AXTCepk0JRlbfsqAj+zbd7OmyMBKUqls8OvZNwtKLxbGT9Dq7VXiq5Gkhk+FSJ4
MgPOZL2tKlYdtuwotBZefL2KKR18nwGpcnM7uuj8fzhBriocztl0ggKj8BR3wtbi
MOY9xM0IsbZ5mm8DQ5LeoKaogYe4rL/1mHY36lFBpW3BxKgPGFu67RvouIPkGe3J
VaSExujiz2kZZOJE2QM4kl1YEZrfoD/mJIQS9UxIPd7YJ/CAVPy/rjjlyH/tLfpB
tgT25rYnrvwS/8p0V+Iw9siSJVL5FgaMBKJuaa+++J9/jhNRp9IR7RPAN5azzE7T
h/SVwr5/lXoMscTEXRwBbvXw8KutJDR8wqP2JfmQWBlPrCTUG2PLkxLXs6BZjuQ/
lwv7j77R58T52yfREuF5yPE7XH5YMgvPAZ+UU+k=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF6TCCA9GgAwIBAgIUJzdYkpD6DXiGkfTlgiBn5yp02zQwDQYJKoZIhvcNAQEL
BQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExJTAjBgNVBAoM
HFRoZSBBY21lIFdpZGdldHMgQ29ycG9yYXRpb24xEDAOBgNVBAsMB0lzc3VlcnMx
HzAdBgNVBAMMFlJvb3QgSXNzdWluZyBBdXRob3JpdHkwHhcNMjYwNzExMDAwMzM0
WhcNMzYwNzA4MDAwMzM0WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv
cm5pYTElMCMGA1UECgwcVGhlIEFjbWUgV2lkZ2V0cyBDb3Jwb3JhdGlvbjEQMA4G
A1UECwwHSXNzdWVyczEfMB0GA1UEAwwWUm9vdCBJc3N1aW5nIEF1dGhvcml0eTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL+o66CL8CagzMbaUApk3lG4
tXncHDPnCO1CFTLY5qL4vJnFLfy0lmrt19+RywpNbqj7wECXKzHOCnFt1uzHQfaZ
9xHfepL2J619JcOqIyeHr0P7izclie/Wfi+2Z/Tr1yUr6iqmsZoI+1kRhcDYqRw+
aOsqubyAnkK8wAndVV2v14/o+mnHL1FKMzZfSPiYsTwHNR4SZd7vymkRffndpxGZ
WTIgiY6LwZBgRfu9WilyL6A3h74IvqMai3DNVg7Ja70nWbu/j5sEEzskSF+o/5/i
Zb9eyzVCb9LRkVhUvCdnJqZX2lqcIVWfQuIBGfsVw8tiYDVfQkcaw4KP/udC258R
iNbI+r6h+nMmkwxi66cTLGfTUoSNwONCv9YnZZf88K6qsiv/bXZb6R7whT52sWUs
I+mjx1+ylhKHUubLdfAnOYbJ45peJundkoy2Rt2LQoTQBwkSxIoBJOCFJ+/G3JjR
WfiJTvnIXAhMhRFLI9Y0hHbpYdoi1JgXmquWMOnN/Up/pu77rdeRJ+bO6n8dm+/I
2ArGD4IS+ANSoKdS6lwVkn7v+BDKj883gqf+daTOTJhSAFXH6uIHcC1E7aCzi29e
Mwng1wS94vuNg6yr/aHf+hziWSJ6vdG9kabvqq6ddFx0ac/VqAIiqRQC2goUIcv/
YNggg4Pf4D1XZY+fadjBAgMBAAGjYzBhMB0GA1UdDgQWBBRYqN/8zoqqUU+iZ+bz
KAu/59x4VjAfBgNVHSMEGDAWgBRYqN/8zoqqUU+iZ+bzKAu/59x4VjAPBgNVHRMB
Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAt2H3
V8h+8OiTWruz51p3wiWLkOqtm/SSqs2xtBZkmcOxE5L5+pDkrNBgVmjURjmmte8y
5JcAiOpQF+9Llkp5lxlM3P60KLYRJ0vxNJe+egbMfIzsj5XWAIjYnGCQp1UmmOjY
fIFBnjHonnq6KmhzNZ4vNZdT7DD/Rha4Knm6zx13CijkDOKrHo4UsFE6KQHZcK8k
lnTGaHmdFf5nL+o/U4fqraX1rnnS95GVDumVheBFsnGHJthLsAM92u+SlXYttUqR
K/npl0NRTxdsSNu6YLkZ6cjIa0Tzv9xdFSWnPbQhRsrAzroTzScJyfUWPEp2Da8S
BEEVln8fAo7EXdV73BlAiYgryeUkhu0bNsL4r1DLsKzAK3LvNnGuC4z1QgprZsdh
sMHyrWiFGex6s1FLrGWm+vqR7lp0PWyoVyIKtNu8nMNTtXETPxKa3OG6cCGXQEEz
pWvmPlDGsY2zHsCA1PVvCamjCuZCZfu3B1sE/2xOf+HRMaEUX64Cr5A4ieHOIcid
FMyCQxrxxup6DjN8MgPxWAp5TdHPuML17Mwh7E5smpyauajlglZ/D6MlxmZLUeNt
Y2rX8ecKrPvDQfs2lMXQQx9D5BXhOuiQ+6GAOGJdZtUz6ro3M5C04V+ZsHkdkOuX
1dguDcLmIKVWypfotSf5sTzavQTEuzoPWZMfsak=
-----END CERTIFICATE-----
`)

/*
usersCRL contains an X.509 certificate revocation list, which
has exactly one entry (revoked user). In a real production
environment, this would be regularly updated. Alternatively,
one could go with OCSP, but that has its own caveats ...

This can be examined via:

  $ openssl crl -text -in /path/to/the/crl/file
*/
var usersCRL []byte = []byte(`-----BEGIN X509 CRL-----
MIIDMDCCARgCAQEwDQYJKoZIhvcNAQELBQAwgYoxCzAJBgNVBAYTAlVTMRMwEQYD
VQQIDApDYWxpZm9ybmlhMSUwIwYDVQQKDBxUaGUgQWNtZSBXaWRnZXRzIENvcnBv
cmF0aW9uMRAwDgYDVQQLDAdJc3N1ZXJzMS0wKwYDVQQDDCRVc2VycyBJbnRlcm1l
ZGlhdGUgSXNzdWluZyBBdXRob3JpdHkXDTI2MDcxMTAxNTkzMVoXDTI2MDgxMDAx
NTkzMVowJzAlAhRD6eh3HsmEWt3hBZKe0Wkmg8Fb5RcNMjYwNzExMDE1OTE1WqAw
MC4wHwYDVR0jBBgwFoAUOruCC3SGosxBplEBkSVQy8rln3QwCwYDVR0UBAQCAhAC
MA0GCSqGSIb3DQEBCwUAA4ICAQAQZdtXzWcDSrB8I/YpC7X0U4Ebdo3Wx1cbWn0+
CdwM0DlX0y3TFRfmhO/HvfQMrX2e1pyL19jgdDlma+SadoiEkIAvI+WoR+ZEluqf
ezPNI/OxdR96me+Q/XA7bcoRAtYGbSoejzms7hB/OF9E6SIP67uXTrGZTOOsuToO
maZ4y/OSPzhxewjL7WdzwbmiFSQXOspEN15zzMalHYEMzeHNtdQfn4s0t/iOO682
gZ3cwbSMB+bgkfQQ413TQN6vBNQf++U6TBNtK5XximJF2Pg+YHkqWz0j9tPlyGOh
J3bSUeEPRXr6czH/+f/HRWWnuzyf43XJwt9qlrJ2qi1gJk76lWslifUX0bRYQfJN
MsCRGVxMaCaQt7EU0ZvJhYchwLBdR8xeb7Oj65aLQzv8SNE4yRb1Ren/ENf5S9sN
MS243tVajfFZvDodm10gd8a0PM+m3smDgNnBhCfjrWIDSvtSdT4Ui+/FVGgiiR/o
He+ZMMKizZzbtyx7GvFdYI2/EpbGdGq9+7ToWxjYPp315MQ28GS10RE69SJZ1o04
+rxp8Uotzw4XZvU1A9AtStMKxAvYhkgFAr8EzWhq5ZXBmba06HxjuSSJ5Se53xd4
22GXk1CfEBJ9gSSoEkZrO0ry+zKYqSzKsZqkD7TFxSj5xGVR2EYpG/j3qRT+B0Mi
D5WNZg==
-----END X509 CRL-----
`)
