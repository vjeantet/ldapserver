# sasl_mtls

This example extends from "examples/complex" by implementing the following sections:

### X.509 client certificate processing, CA check, CRL check

This example also addresses what appears to be a bad private key embedded in the original example. While testing the original example, I received errors complaining about "bad rsa data".

But, using my own test key and certificate pair seemed to fixed the issue, so I generated the following PKI elements:

  - Valid _server_ certificate and private key
  - Valid _client_ certificate and private key
  - Revoked _client_ certificate and private key
  - Expired _client_ certificate and private key
  - Issuing authority certificate (private key not needed)
  - Certificate revocation list for our issuer certificate

The included CA certificate is the issuer for the "Valid", "Revoked" and "Expired" certificates, and is the CA used in generating the certificate revocation list (CRL). The CRL contains exactly one revocation entry. The private keys for the issuer certificates are not included as they are not needed for this demo to succeed.

The _server_ certificate and private key are embedded as raw PEM string constants, and are used only for the TLS/LDAP listener.

The _client_ certificates and private keys are actual files and are meant for the end user. See the "SASL/EXTERNAL Mechanism" section for details.

### SASL/EXTERNAL Mechanism

The SASL/EXTERNAL mechanism is generally used for client certificates or hardware crypto devices. It is called "EXTERNAL" because identities are verified via a PKI implementation and not by any directory content in particular.

That is, rather than doing a simple bind, i.e.:

```bash
$ ldapwhoami -xWD cn=Jesse Coretta,ou=Consultants,ou=Accounts,o=Acme
```

... we instead feed it an X.509 certificate. Generally the easiest way to do this is with OpenLDAP's client package and your own personal `~/.ldaprc` file.  For example:

```
URI        ldap://127.0.0.1:10389
SASL_MECH  EXTERNAL
TLS_CACERT /path/to/issuer-bundle.pem

## VALID client cert/key
TLS_CERT /path/to/valid_user/cert.pem
TLS_KEY  /path/to/valid_user/priv.key

## REVOKED client cert/key
#TLS_CERT /path/to/revoked_user/cert.pem
#TLS_KEY  /path/to/revoked_user/priv.key

## EXPIRED client cert/key
#TLS_CERT /path/to/expired_user/cert.pem
#TLS_KEY  /path/to/expired_user/priv.key
```

<sub>NOTE: You can also opt for env. var parameters instead of `.ldaprc`</sub>

The revoked and expired `TLS_CERT` and `TLS_KEY` "pairs" are commented out. Simply comment out the valid pair and uncomment the desired one.

To test, use `ldapwhoami` with TLS criticality (non opportunistic) using our valid client certificate and key:

```bash
## VALID client certificate
$ ldapwhoami -ZZ
SASL/EXTERNAL authentication started
SASL username: <the X.509 subject DN>
SASL SSF: 0
ldap_bind: Success (0)
	additional info: dn:<the LDAP DN>
```

<sub>NOTE: use "-Q" to silence SASL output</sub>

Note that, unlike the GSSAPI mechanism, et al., the SASL SSF is always zero (0) when the EXTERNAL mechanism is used. Don't worry, your certificate's got it covered :)

### Authorization identity handling

Once you perform a SASL/EXTERNAL bind, by default the Subject DN of that certificate is reformatted into an equivalent LDAP DN. For instance, this X.509 subject DN:

`/CN=Jesse Coretta/O=The Acme Widgets Corporation/C=US`

 ... this would translate to an LDAP DN of:

`cn=Jesse Coretta,o=Acme Corp,c=US`

But seldom do certificate DNs map naturally to a directory structure. This is where identity mapping comes into play.

Most modern directory products offer some kind of identity mapping system for scenarios just like this.  Most often they manifest as configuration parameters, or even separate configuration files altogether. For the sake of simplicity, this example mimics OpenLDAP's `authz-regex` parameter in `slapd.conf`.

The idea is simple: write a regular expression meant to parse the incoming identity (i.e.: the certificate's subject DN), and map the captured groups to a "template" DN. For instance:

```
  "(?i)^CN=([^,]+),OU=.+,O=The Acme Widgets Corporation,C=US$", // pattern
  "cn=$1,ou=People,o=Acme"				        // template
```

This example provides a facility to build a policy "stack".

```go
	var policies AuthzRegexPolicies
        policies.Push(`your_pattern`,`your_template`)
        policies.Push(`other_pattern`,`other_template`)
        policies.Push(`specific_dn`,`target_dn`) // no regex, just an explicit 1-to-1 mapping
	// .. etc ..

	// Later, we submit an incoming identity for
	// analysis. First successful match wins.
	dn, ok := policies.Apply(`incoming_dn`)
	if ok {
		// use your newly mapped DN
	}
```

If an identity did not match a particular policy, the original identity is used as a best-effort fallback.

The mapped identity does not necessarily have to exist as a directory entry. The lack of an actual entry will not interfere with an ***explicit mapping*** as done above.

## Demo Limitations

This example does NOT (yet) implement any internal searches to verify the presence of an associated entry (e.g.: `ldap:///cn=$1,ou=People,o=Acme??base`). This feature is planned for a future revision of this example.

This example does NOT (yet) account for a single `-Z` CLI flag to encrypt in an _opportunistic_ manner. Instead, the demo expects `-ZZ` (TLS w/ _criticality_), which means a successful TLS handshake is **strictly required**.
