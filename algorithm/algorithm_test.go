package algorithm

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromName(t *testing.T) {
	testCases := []struct {
		name     string
		expected Algorithm
	}{
		{"EC", EC},
		{"RSA", RSA},
		{"PBEWithMD5AndDES", PBEWithMD5AndDES},
		{"PBEWithMD5AndTripleDES", PBEWithMD5AndTripleDES},
		{"1.3.6.1.4.1.42.2.19.1", JCEKeyProtector},
		{"foo", Algorithm{"foo", nil}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := FromName(tc.name)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestFromOID(t *testing.T) {
	testCases := []struct {
		oid      asn1.ObjectIdentifier
		expected Algorithm
	}{
		{asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, EC},
		{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, RSA},
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 19, 1}, JCEKeyProtector},
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}, JDKKeyProtector},
		{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}, PBEWithMD5AndDES},
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 47240}, Algorithm{"1.3.6.1.4.1.47240", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 47240}}},
	}

	for _, tc := range testCases {
		t.Run(tc.oid.String(), func(t *testing.T) {
			actual := FromOID(tc.oid)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
