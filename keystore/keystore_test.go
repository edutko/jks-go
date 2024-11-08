package keystore

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoadFromFile(t *testing.T) {
	password := loadPassword()
	testCases := []struct {
		name     string
		password string
	}{
		{"cacerts", DefaultPasswordMacOSCacerts},
		{"certs.jks", password},
		{"certs-jce.jks", password},
		{"certs-and-keys-jce.jks", password},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := parseKeystoreDump("testdata/" + strings.TrimSuffix(tc.name, ".jks") + ".json")

			k, err := LoadFromFile("testdata/"+tc.name, tc.password)

			assert.Nil(t, err)
			assert.Equal(t, info.Type, k.Format)
			assert.Len(t, k.Entries, len(info.Entries))
			for _, e := range k.Entries {
				expected, ok := info.Entries[e.Alias]

				assert.True(t, ok)
				assert.Equal(t, expected.Type, e.Type)
				assert.WithinDuration(t, expected.Date, e.Date, 0)

				switch expected.Type {
				case TrustedCertEntry:
					assert.Len(t, e.Certificates, len(expected.Certs))
					for i := range expected.Certs {
						assert.Equal(t, expected.Certs[i].Type, e.Certificates[i].Type)
						assert.Equal(t, expected.Certs[i].Bytes, e.Certificates[i].Bytes)
					}

				case SecretKeyEntry:
					decrypted, _ := e.Decrypt(password)
					assert.Equal(t, expected.Algorithm, decrypted.Algorithm.Name)
					assert.Equal(t, expected.Format, decrypted.Format)
					assert.Equal(t, expected.Key, decrypted.Bytes)

				case PrivateKeyEntry:
					decrypted, _ := e.Decrypt(password)
					assert.Equal(t, expected.Algorithm, decrypted.Algorithm.Name)
					assert.Equal(t, expected.Format, decrypted.Format)
					assert.Equal(t, expected.Key, decrypted.Bytes)

					assert.Len(t, e.Certificates, len(expected.Certs))
					for i := range expected.Certs {
						assert.Equal(t, expected.Certs[i].Type, e.Certificates[i].Type)
						assert.Equal(t, expected.Certs[i].Bytes, e.Certificates[i].Bytes)
					}
				}
			}
		})
	}
}

func TestLoadFromFile_PKCS12(t *testing.T) {
	testCases := []struct {
		name     string
		password string
	}{
		{"cacerts-pkcs12", ""},
		// TODO: modify pkcs12 library to support safes with multiple authenticated items
		//{"certs-pkcs12.jks", password},
		//{"certs-and-keys-pkcs12.jks", password},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := parseKeystoreDump("testdata/" + strings.TrimSuffix(tc.name, ".jks") + ".json")

			k, err := LoadFromFile("testdata/"+tc.name, tc.password)

			assert.Nil(t, err)
			assert.Equal(t, info.Type, k.Format)
			assert.Len(t, k.Entries, len(info.Entries))
			for _, e := range k.Entries {
				// TODO: modify pkcs12 library to capture alias
				//expected, ok := info.Entries[e.Alias]
				//assert.True(t, ok)
				// TODO: modify pkcs12 library to capture entry type
				//assert.Equal(t, expected.Type, e.Type)
				// TODO: modify pkcs12 library to capture date
				//assert.Equal(t, expected.Date, truncateDate(e.Date))
				// TODO: modify pkcs12 library to capture all certs
				//if expected.Type == PrivateKeyEntry || expected.Type == TrustedCertEntry {
				//	assert.Equal(t, expected.Fingerprint, sha256.Sum256(e.Certificates[0].Raw))
				//}
				assert.Len(t, e.Certificates, 1)
			}
		})
	}
}

func loadPassword() string {
	b, err := os.ReadFile("testdata/password")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func parseKeystoreDump(name string) keystoreInfo {
	data, err := os.ReadFile(name)
	if err != nil {
		panic(err)
	}

	var k keystoreInfo
	err = json.Unmarshal(data, &k)
	if err != nil {
		panic(err)
	}

	return k
}

type keystoreInfo struct {
	Type    Type                 `json:"type"`
	Entries map[string]entryInfo `json:"entries"`
}

type entryInfo struct {
	Date      time.Time  `json:"creationDate"`
	Type      EntryType  `json:"entryType"`
	Algorithm string     `json:"algorithm"`
	Format    string     `json:"format"`
	Key       []byte     `json:"key"`
	Certs     []certInfo `json:"certs"`
}

type certInfo struct {
	Type  string `json:"type"`
	Bytes []byte `json:"bytes"`
}
