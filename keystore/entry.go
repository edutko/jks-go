package keystore

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/edutko/cafegopher/java"
	javalang "github.com/edutko/cafegopher/java/lang"

	javaxcrypto "github.com/edutko/jks-go/crypto"
)

type EntryType string

// These strings were selected to match the output of `keytool -list`
const (
	PrivateKeyEntry  EntryType = "PrivateKeyEntry"
	TrustedCertEntry EntryType = "trustedCertEntry"
	SecretKeyEntry   EntryType = "SecretKeyEntry"
)

type KeystoreEntry struct {
	Type         EntryType
	Alias        string
	Date         time.Time
	Certificates []*x509.Certificate
	EncryptedKey struct {
		Bytes        []byte
		CipherParams CipherParameters
		SealAlg      string
		ParamAlg     string
	}
}

type CipherParameters struct {
	Salt   []byte
	Rounds int
}

type PrivateKey struct {
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func (e KeystoreEntry) EncryptionAlgorithm() string {
	if e.EncryptedKey.SealAlg == "" {
		var k PrivateKey
		_, err := asn1.Unmarshal(e.EncryptedKey.Bytes, &k)
		if err != nil {
			return "unknown"
		}
		return k.Algo.Algorithm.String()
	}
	return e.EncryptedKey.SealAlg
}

func (e KeystoreEntry) Decrypt(password string) ([]byte, error) {
	k := e.EncryptedKey
	alg := e.EncryptionAlgorithm()
	switch alg {
	case OIDJDKKeyProtector.String():
		var priv PrivateKey
		_, err := asn1.Unmarshal(e.EncryptedKey.Bytes, &priv)
		if err != nil {
			return nil, err
		}
		return javaxcrypto.DecryptJKSEntry(priv.PrivateKey, javalang.String(password)), nil

	case OIDJCEKeyProtector.String():
		var priv PrivateKey
		_, err := asn1.Unmarshal(e.EncryptedKey.Bytes, &priv)
		if err != nil {
			return nil, err
		}
		var params CipherParameters
		_, err = asn1.Unmarshal(priv.Algo.Parameters.FullBytes, &params)
		if err != nil {
			return nil, err
		}
		return javaxcrypto.DecryptPBEWithMD5AndTripleDES(priv.PrivateKey, javalang.String(password), params.Salt, params.Rounds), nil

	case "PBEWithMD5AndTripleDES":
		plaintext := javaxcrypto.DecryptPBEWithMD5AndTripleDES(k.Bytes, javalang.String(password), k.CipherParams.Salt, k.CipherParams.Rounds)
		var sks secretKeySpec
		err := java.Unmarshal(plaintext, &sks)
		if err == nil {
			return sks.Key, nil
		}
		var kr keyRep
		err = java.Unmarshal(plaintext, &kr)
		if err == nil {
			return kr.Encoded, nil
		}
		return nil, err

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm")
	}
}

var OIDJDKKeyProtector = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}
var OIDJCEKeyProtector = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 19, 1}
