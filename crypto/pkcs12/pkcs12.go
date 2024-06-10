package pkcs12

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"software.sslmate.com/src/go-pkcs12"
)

func MaybePKCS12(data []byte) bool {
	var p pfxPdu
	rest, err := asn1.Unmarshal(data, &p)
	if err != nil {
		return false
	}
	return len(rest) == 0
}

func DecodeTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
	return pkcs12.DecodeTrustStore(pfxData, password)
}

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

// from PKCS#7:
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}
