package keystore

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/edutko/jks-go/algorithm"
)

func TestKeystoreEntry_ParseCertificates(t *testing.T) {
	testCases := []struct {
		name     string
		entry    Entry
		expected []*x509.Certificate
	}{
		{"p256.crt",
			Entry{Type: TrustedCertEntry},
			[]*x509.Certificate{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.entry.EncryptedKey.Bytes = loadEntry(filepath.Join("testdata", "entries", tc.name))

			certs, err := tc.entry.ParseCertificates()

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, certs)
		})
	}
}

func TestKeystoreEntry_Decrypt(t *testing.T) {
	password := loadPassword()

	testCases := []struct {
		name     string
		entry    Entry
		expected *Key
	}{
		{"aes128",
			Entry{Type: SecretKeyEntry, EncryptedKey: EncryptedKey{
				CipherParams: CipherParameters{Salt: unhex("e73716c46f1fd277"), Rounds: 200000},
				SealAlg:      "PBEWithMD5AndTripleDES",
				ParamAlg:     "PBEWithMD5AndTripleDES",
				Bytes:        loadEntry(filepath.Join("testdata", "entries", "aes128")),
			}},
			&Key{
				Algorithm: algorithm.AES,
				Format:    "RAW",
				Bytes:     unb64("DdAu8mEqblnirmZUPGaTdw=="),
			},
		},
		{"p256.crt",
			Entry{Type: TrustedCertEntry},
			nil,
		},
		{"p256.key",
			Entry{Type: PrivateKeyEntry, EncryptedKey: EncryptedKey{
				SealAlg: "1.3.6.1.4.1.42.2.19.1",
				Bytes:   loadEntry(filepath.Join("testdata", "entries", "p256.key")),
			}},
			&Key{
				Algorithm: algorithm.EC,
				Format:    "PKCS#8",
				Bytes:     unb64("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCA6fN1BHSqsxi2Nx1EDw8o5KK0rvbU6EAK9xNeJXJd06Q=="),
			},
		},
		{"password",
			Entry{Type: SecretKeyEntry, EncryptedKey: EncryptedKey{
				CipherParams: CipherParameters{Salt: unhex("bbbb520459a91c99"), Rounds: 200000},
				SealAlg:      "PBEWithMD5AndTripleDES",
				ParamAlg:     "PBEWithMD5AndTripleDES",
				Bytes:        loadEntry(filepath.Join("testdata", "entries", "password")),
			}},
			&Key{
				Algorithm: algorithm.PBEWithMD5AndDES,
				Format:    "RAW",
				Bytes:     []byte("monkey123"),
			},
		},
		{"rsa2048.key",
			Entry{Type: PrivateKeyEntry, EncryptedKey: EncryptedKey{
				SealAlg: "1.3.6.1.4.1.42.2.19.1",
				Bytes:   loadEntry(filepath.Join("testdata", "entries", "rsa2048.key")),
			}},
			&Key{
				Algorithm: algorithm.RSA,
				Format:    "PKCS#8",
				Bytes:     unb64("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC6s6XQ0hGtdfhRblW7D4v4jooz967TnoF6scZ2Pk8hMqU7krSCoHBsLI8WYlpkMMuE91L28qicJkWDmbFbuA/oq1Ji8XK6eUJUrtWA/f1X28VIRyJItdDg9wU6TQ0owZQB0Fy6M/RJgiM0BsxvzDDkLsc8n8m1Vx05nJ4Nz/1lnVcaBoTBeURQEVWD5hpzVosaJMz1HEIclLWP8u82Bxg81mMnkz4xrDNIt06aVmf2I4LOklxK+jCx90gRO0Z4EJBlNbOg4MHjKrEl7SNIetn/g+VxRKTf73v+1ZAimac2JSNTI6eG0N9BoH83fZHRAPFrcqj3otJjnOfY3t+pRmyrAgMBAAECggEAOiWXP/kc7lQueVYOt0q5QjlKi7LZLSlRlB/n+o2fYWx/j5U6SPCk8tvR2JvbIRcdW5UXrreWkcNNpRXp6fHiaolpCE3AeJkpcmxdLGZuT72vrLoS0Ghn3JiydRzoO0hGy2XUa12g+H/ibOKtKyiCFZ8ICDaPwL2X6YiApTag6dNUy+eENpH94i+2n+DZPzr2oEUVeKaFZ7ouEPYFYNKTEgsHN0nMYNVQ0WBw3cqLN9s2aARSxSsyTB3BN9I7esSJ0uZkDX1zB6/5Mlxb+m7sLZD3x6hUNhv5cRHPtkY954ho3o38wR0faBWoTuEkrufFKtnzGx+sTd1UQmWabRRHiQKBgQDBj2RUJ5jtjzwcZ3VMGntACE6hDUmVN57XCr9Ebe6K1eop0SaUEJ2iOz1OuEe0eupDQjNPzjEGcftrgRUPCBz3V6O5NtW1ygx68fZW+IlGGlDNAOnEoqHW1ev17vOJU7sdcHiFzW1IjtPkXIFgYB43L87ZgvS9ya3MncBhIDIptQKBgQD27eBiqy6cAmV2Hys+v/OKCpp2CJvG93PyUqFetv0mG9spyzSKymgCg4VihmS6cydPPF4cXBnhk4CHhPS4lb275wZyOCgDassLpJYn35QuLxv5ylG4w3P0cFmbgUxv9rqKCytSf+86RZ47M5C/xRazoMEMAkW2A254r80sKXK43wKBgGlq3ByNOFfhk75whky9e3TDUXebUgEHuuWpf8QYDzvkB1VhCJ7JceDCXMB70umzq9SXwHRtevvkpibFtZ9rLsNzIsMj3z7T3Po0v5JcZ/8bI/iSz759SKFF/u4Bhve694SwFaPh3uwOhc6wpvHDR5GM4x5JmVun9JUlMXp0W32lAoGARdfo1N/IcjY3Tp7oU3plv1DaebJbpX6OnCcFH84wclwEtKCWfv9bRgK/cqvCx/4US1Qu5mSiqWxYOXzA34jzPrfM2ffKUZUeU2+9TQ/vUNTgW9n/HXyjSquQnOyIm061WqBoI5CuMNRKOkKOmb98eVhp4iSuZRo5YAeRyAD9Qw8CgYBl3wvOvkSxiRN93NuWcVrCYbC2tBbnhy8gkc+zC0spgPtCK7Cxu93PhkXHm3tW62OZZlqnJk6XL1LsDg6dYg9diYaQYjfT8QBMkg8NNSD3R8rY9oDWSgnxitjgaKqUpWq04tBqkJPR7HlgoOjrve7BXaMvthy38FIrR46sUR1sUQ=="),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := tc.entry.Decrypt(password)

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, k)
		})
	}
}

func loadEntry(name string) []byte {
	b, err := os.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func unb64(b64 string) []byte {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic(err)
	}
	return b
}
