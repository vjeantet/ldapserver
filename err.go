package ldapserver

import (
	"fmt"
	ldap "github.com/lor00x/goldap/message"
)

var (
	errIsNotPack0x30 = ldap.LdapError{Msg: fmt.Sprintf("Expecting 0x30 as first byte")}
)
