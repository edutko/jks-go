package algorithm

import (
	"encoding/asn1"
	"strings"
)

type Algorithm struct {
	Name string
	OID  asn1.ObjectIdentifier
}

// https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html
var (
	None    = Algorithm{}
	Unknown = Algorithm{"unknown", nil}

	AES                    = Algorithm{"AES", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1}}
	ARCFOUR                = Algorithm{"ARCFOUR", asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 4}}
	Blowfish               = Algorithm{"Blowfish", nil}
	ChaCha20               = Algorithm{"ChaCha20", nil}
	DES                    = Algorithm{"DES", nil}
	DESede                 = Algorithm{"DESede", asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 17}}
	DH                     = Algorithm{"DH", asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}}
	DSA                    = Algorithm{"DSA", asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}}
	EC                     = Algorithm{"EC", asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}}
	Ed25519                = Algorithm{"Ed25519", asn1.ObjectIdentifier{1, 3, 101, 112}}
	Ed448                  = Algorithm{"Ed448", asn1.ObjectIdentifier{1, 3, 101, 113}}
	JCEKeyProtector        = Algorithm{"JCEKeyProtector", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 19, 1}}
	JDKKeyProtector        = Algorithm{"JDKKeyProtector", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}}
	PBEWithMD5AndDES       = Algorithm{"PBEWithMD5AndDES", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}}
	PBEWithMD5AndTripleDES = Algorithm{"PBEWithMD5AndTripleDES", nil}
	PBEWithSHA1AndDESede   = Algorithm{"PBEWithSHA1AndDESede", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}}
	PBEWithSHA1AndRC2_128  = Algorithm{"PBEWithSHA1AndRC2_128", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}}
	PBEWithSHA1AndRC2_40   = Algorithm{"PBEWithSHA1AndRC2_40", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}}
	PBEWithSHA1AndRC4_128  = Algorithm{"PBEWithSHA1AndRC4_128", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 1}}
	PBEWithSHA1AndRC4_40   = Algorithm{"PBEWithSHA1AndRC4_40", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 2}}
	RC2                    = Algorithm{"RC2", asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 2}}
	RSA                    = Algorithm{"RSA", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}}
	X25519                 = Algorithm{"X25519", asn1.ObjectIdentifier{1, 3, 101, 110}}
	X448                   = Algorithm{"X448", asn1.ObjectIdentifier{1, 3, 101, 111}}
)

func FromName(name string) Algorithm {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, alg := range all {
		if name == strings.ToLower(alg.Name) {
			return alg
		}
		if alg.OID != nil && name == alg.OID.String() {
			return alg
		}
	}
	return Algorithm{name, nil}
}

func FromOID(o asn1.ObjectIdentifier) Algorithm {
	for _, alg := range all {
		if alg.OID != nil && o.Equal(alg.OID) {
			return alg
		}
	}
	return Algorithm{o.String(), o}
}

var all = []Algorithm{
	AES,
	ARCFOUR,
	Blowfish,
	ChaCha20,
	DES,
	DESede,
	DH,
	DSA,
	EC,
	Ed25519,
	Ed448,
	JCEKeyProtector,
	JDKKeyProtector,
	PBEWithMD5AndDES,
	PBEWithMD5AndTripleDES,
	PBEWithSHA1AndDESede,
	PBEWithSHA1AndRC2_128,
	PBEWithSHA1AndRC2_40,
	PBEWithSHA1AndRC4_128,
	PBEWithSHA1AndRC4_40,
	RC2,
	RSA,
	X25519,
	X448,
}
