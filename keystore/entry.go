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
	"github.com/edutko/jks-go/oid"
)

type EntryType string

// These strings were selected to match the output of `keytool -list`
const (
	PrivateKeyEntry  EntryType = "PrivateKeyEntry"
	TrustedCertEntry EntryType = "trustedCertEntry"
	SecretKeyEntry   EntryType = "SecretKeyEntry"
)

type Key struct {
	Algorithm string
	Format    string
	Bytes     []byte
}

type KeystoreEntry struct {
	Type         EntryType
	Alias        string
	Date         time.Time
	Certificates []*x509.Certificate
	EncryptedKey
}

type EncryptedKey struct {
	Bytes        []byte
	CipherParams CipherParameters
	SealAlg      string
	ParamAlg     string
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

func (e KeystoreEntry) Decrypt(password string) (*Key, error) {
	k := e.EncryptedKey
	switch e.EncryptionAlgorithm() {
	case oid.JDKKeyProtector.String():
		var priv PrivateKey
		_, err := asn1.Unmarshal(k.Bytes, &priv)
		if err != nil {
			return nil, err
		}
		b := javaxcrypto.DecryptJKSEntry(priv.PrivateKey, javalang.String(password))
		var sk pkcs8
		_, err = asn1.Unmarshal(b, &sk)
		return &Key{
			Algorithm: oid.NameOf(sk.Algo.Algorithm),
			Format:    "PKCS#8",
			Bytes:     b,
		}, err

	case oid.JCEKeyProtector.String():
		var priv PrivateKey
		_, err := asn1.Unmarshal(k.Bytes, &priv)
		if err != nil {
			return nil, err
		}
		var params CipherParameters
		_, err = asn1.Unmarshal(priv.Algo.Parameters.FullBytes, &params)
		if err != nil {
			return nil, err
		}
		b := javaxcrypto.DecryptPBEWithMD5AndTripleDES(priv.PrivateKey, javalang.String(password), params.Salt, params.Rounds)
		var sk pkcs8
		_, err = asn1.Unmarshal(b, &sk)
		return &Key{
			Algorithm: oid.NameOf(sk.Algo.Algorithm),
			Format:    "PKCS#8",
			Bytes:     b,
		}, err

	case "PBEWithMD5AndTripleDES":
		plaintext := javaxcrypto.DecryptPBEWithMD5AndTripleDES(k.Bytes, javalang.String(password), k.CipherParams.Salt, k.CipherParams.Rounds)
		var sks secretKeySpec
		err := java.Unmarshal(plaintext, &sks)
		if err == nil {
			return &Key{
				Algorithm: sks.Algorithm,
				Format:    "RAW",
				Bytes:     sks.Key,
			}, nil
		}
		var kr keyRep
		err = java.Unmarshal(plaintext, &kr)
		if err == nil {
			return &Key{
				Algorithm: kr.Algorithm,
				Format:    kr.Format,
				Bytes:     kr.Encoded,
			}, nil
		}
		return nil, err

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm")
	}
}

type keyRep struct {
	Algorithm string `java:"java.security.KeyRep.algorithm"`
	Encoded   []byte `java:"java.security.KeyRep.encoded"`
	Format    string `java:"java.security.KeyRep.format"`
	//Type      string `java:"java.security.KeyRep.type"`
}

type secretKeySpec struct {
	Algorithm string `java:"javax.crypto.spec.SecretKeySpec.algorithm"`
	Key       []byte `java:"javax.crypto.spec.SecretKeySpec.key"`
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}
