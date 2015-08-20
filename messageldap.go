package ldapserver

// OCTETSTRING ASN.1 types
type OCTETSTRING string

// LDAPOID is a notational convenience to indicate that the
// permitted value of this string is a (UTF-8 encoded) dotted-decimal
// representation of an OBJECT IDENTIFIER.  Although an LDAPOID is

// LDAPDN is defined to be the representation of a Distinguished Name
// (DN) after encoding according to the specification
type LDAPDN string

// respectively, and have the same single octet UTF-8 encoding.  Other
// Unicode characters have a multiple octet UTF-8 encoding.
type LDAPString string

//
//        AttributeDescription ::= LDAPString
//                                -- Constrained to <attributedescription>
//                                -- [RFC4512]
type AttributeDescription LDAPString

//        AttributeValue ::= OCTET STRING
type AttributeValue OCTETSTRING

//
//        PartialAttribute ::= SEQUENCE {
//             type       AttributeDescription,
//             vals       SET OF value AttributeValue }
type PartialAttribute struct {
	type_ AttributeDescription
	vals  []AttributeValue
}

func (p *PartialAttribute) GetDescription() AttributeDescription {
	return p.type_
}
func (p *PartialAttribute) GetValues() []AttributeValue {
	return p.vals
}

//
//        PartialAttributeList ::= SEQUENCE OF
//                             partialAttribute PartialAttribute
type PartialAttributeList []PartialAttribute

func (l *PartialAttributeList) add(p PartialAttribute) {
	*l = append(*l, p)
}
