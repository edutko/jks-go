package keystore

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
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
		{"cacerts", "changeme"},
		{"certs.jks", password},
		{"certs-jce.jks", password},
		{"certs-and-keys-jce.jks", password},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := parseKeytoolListOutput("testdata/" + tc.name + ".list")

			k, err := LoadFromFile("testdata/"+tc.name, tc.password)

			assert.Nil(t, err)
			assert.Equal(t, info.Format, k.Format)
			assert.Len(t, k.Entries, len(info.Entries))
			for _, e := range k.Entries {
				expected, ok := info.Entries[e.Alias]
				assert.True(t, ok)
				assert.Equal(t, expected.Type, e.Type)
				assert.Equal(t, expected.Date, truncateDate(e.Date))
				if expected.Type == PrivateKeyEntry || expected.Type == TrustedCertEntry {
					assert.Equal(t, expected.Fingerprint, sha256.Sum256(e.Certificates[0].Raw))
				}
				if expected.Type == PrivateKeyEntry || expected.Type == SecretKeyEntry {
					plaintext, _ := e.Decrypt(password)
					assert.NotEmpty(t, plaintext)
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
			info := parseKeytoolListOutput("testdata/" + tc.name + ".list")

			k, err := LoadFromFile("testdata/"+tc.name, tc.password)

			assert.Nil(t, err)
			assert.Equal(t, info.Format, k.Format)
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

func truncateDate(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local)
}

func loadPassword() string {
	b, err := os.ReadFile("testdata/password")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func parseKeytoolListOutput(name string) keystoreInfo {
	f, err := os.Open(name)
	if err != nil {
		panic(err)
	}

	var k keystoreInfo
	var count int
	var entries []entryInfo

	s := bufio.NewScanner(f)
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		switch {
		case l == "":
			continue

		case strings.HasPrefix(l, "Keystore type:"):
			k.Format = KeystoreType(strings.TrimSpace(strings.SplitN(l, ":", 2)[1]))

		case strings.HasPrefix(l, "Keystore provider:"):
			continue

		case strings.HasPrefix(l, "Your keystore contains "):
			count, err = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(l, "Your keystore contains "), " entries"))

		case strings.HasPrefix(l, "Certificate fingerprint (SHA-256):"):
			fingerprintString := strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
			fingerprint, _ := hex.DecodeString(strings.ReplaceAll(fingerprintString, ":", ""))
			copy(entries[len(entries)-1].Fingerprint[:], fingerprint)

		default:
			parts := strings.Split(l, ",")
			if len(parts) != 5 {
				panic("unexpected data")
			}
			date := fmt.Sprintf("%s, %s", strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]))
			ts, err := time.ParseInLocation("Jan 2, 2006", date, time.Local)
			if err != nil {
				panic(err)
			}
			entries = append(entries, entryInfo{
				Alias: strings.TrimSpace(parts[0]),
				Date:  ts,
				Type:  EntryType(strings.TrimSpace(parts[3])),
			})
		}
	}

	if count != len(entries) {
		panic("parsing failed")
	}

	k.Entries = make(map[string]entryInfo)
	for _, e := range entries {
		k.Entries[e.Alias] = e
	}

	return k
}

type keystoreInfo struct {
	Format  KeystoreType
	Entries map[string]entryInfo
}

type entryInfo struct {
	Alias       string
	Date        time.Time
	Type        EntryType
	Fingerprint [32]byte
}
