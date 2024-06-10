package keystore

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/edutko/cafegopher/java"
	javalang "github.com/edutko/cafegopher/java/lang"

	javaxcrypto "jks-go/crypto"
)

func readJKSHeader(r io.Reader) (header, error) {
	var h header
	b := make([]byte, 12)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return h, err
	}

	h.Magic = b[:4]
	h.Unknown = b[4:8]
	h.Length = binary.BigEndian.Uint32(b[8:])

	return h, nil
}

type header struct {
	Magic   []byte
	Unknown []byte
	Length  uint32
}

func readJKSEntries(r io.Reader, expected int) ([]KeystoreEntry, error) {
	var es []KeystoreEntry
	for i := 0; i < expected; i++ {
		b := make([]byte, 4)
		_, err := io.ReadFull(r, b)
		if err != nil {
			return nil, err
		}
		typ := binary.BigEndian.Uint32(b)

		e := KeystoreEntry{Type: entryType[int(typ)]}

		e.Alias, err = readString(r)
		if err != nil {
			return nil, err
		}

		e.Date, err = readDate(r)
		if err != nil {
			return nil, err
		}

		switch typ {
		case privateKeyEntry, trustedCertEntry:
			certCount := 1
			if typ == privateKeyEntry {
				l, err := readLength(r, 4)
				if err != nil {
					return nil, err
				}
				e.EncryptedKey.Bytes = make([]byte, l)
				_, err = io.ReadFull(r, e.EncryptedKey.Bytes)
				if err != nil {
					return nil, err
				}

				b = make([]byte, 4)
				_, err = io.ReadFull(r, b)
				if err != nil {
					return nil, err
				}
				certCount = int(binary.BigEndian.Uint32(b))
			}

			certBytes := make([]byte, 0)
			for i := 0; i < certCount; i++ {
				certType, err := readString(r)
				if err != nil {
					return nil, err
				}
				if certType != "X.509" {
					return nil, fmt.Errorf("unexpected certitifacte type: %s", certType)
				}

				l, err := readLength(r, 4)
				if err != nil {
					return nil, err
				}
				rawBytes := make([]byte, l)
				_, err = io.ReadFull(r, rawBytes)
				if err != nil {
					return nil, err
				}
				certBytes = append(certBytes, rawBytes...)
			}
			e.Certificates, err = x509.ParseCertificates(certBytes)
			if err != nil {
				return nil, err
			}

		case secretKeyEntry:
			var so sealedObject
			err = java.UnmarshalReader(r, &so)
			e.EncryptedKey.SealAlg = so.SealAlg
			e.EncryptedKey.ParamAlg = so.ParamsAlg
			e.EncryptedKey.Bytes = so.EncryptedContent
			_, err = asn1.Unmarshal(so.EncodedParams, &e.EncryptedKey.CipherParams)
			if err != nil {
				return nil, err
			}
		}

		es = append(es, e)
	}

	return es, nil
}

const (
	privateKeyEntry  = 1
	trustedCertEntry = 2
	secretKeyEntry   = 3
)

var entryType = map[int]EntryType{
	privateKeyEntry:  PrivateKeyEntry,
	trustedCertEntry: TrustedCertEntry,
	secretKeyEntry:   SecretKeyEntry,
}

func readMAC(r io.Reader) ([]byte, error) {
	mac := make([]byte, sha1.Size)
	_, err := io.ReadFull(r, mac)
	if err != nil {
		return nil, err
	}
	return mac, nil
}

func readLength(r io.Reader, size int) (int, error) {
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, err
	}
	switch size {
	case 2:
		return int(binary.BigEndian.Uint16(b)), nil
	case 4:
		return int(binary.BigEndian.Uint32(b)), nil
	}
	return 0, fmt.Errorf("invalid size: %d", size)
}

func readString(r io.Reader) (string, error) {
	l, err := readLength(r, 2)
	if err != nil {
		return "", err
	}

	b := make([]byte, l)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func readDate(r io.Reader) (time.Time, error) {
	b := make([]byte, 8)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return time.Time{}, err
	}

	u := int64(binary.BigEndian.Uint64(b))

	return time.Unix(u/1000, u%1000), nil
}

func validateStoreMAC(data []byte, keystorePassword javalang.String, expectedMAC []byte) bool {
	computed := javaxcrypto.JavaKeystoreMAC(data, keystorePassword)
	if bytes.Equal(expectedMAC, computed) {
		return true
	}
	return false
}
