package oid

import (
	"encoding/asn1"
)

var JDKKeyProtector = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}
var JCEKeyProtector = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 19, 1}

func NameOf(o asn1.ObjectIdentifier) string {
	switch {
	case o.Equal(asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}):
		return "DSA"
	case o.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}):
		return "RSA"
	case o.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}):
		return "EC"
	case o.Equal(JDKKeyProtector):
		return "JDKKeyProtector"
	case o.Equal(JCEKeyProtector):
		return "JCEKeyProtector"
	case o.Equal(asn1.ObjectIdentifier{1, 3, 101, 110}):
		return "X25519"
	case o.Equal(asn1.ObjectIdentifier{1, 3, 101, 111}):
		return "X448"
	case o.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}):
		return "Ed25519"
	case o.Equal(asn1.ObjectIdentifier{1, 3, 101, 113}):
		return "Ed448"
	default:
		return "unknown"
	}
}
