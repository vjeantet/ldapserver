module github.com/vjeantet/ldapserver

go 1.25.7

require (
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667
	github.com/go-ldap/ldap/v3 v3.4.12
	github.com/lor00x/goldap v0.0.0-20180618054307-a546dffdd1a3
)

replace github.com/lor00x/goldap => github.com/vjeantet/goldap v0.0.0-20260217225510-5e853b323c98

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
)
