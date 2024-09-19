package keystore

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/edutko/cafegopher/java"
	javalang "github.com/edutko/cafegopher/java/lang"

	"github.com/edutko/jks-go/algorithm"
	javaxcrypto "github.com/edutko/jks-go/crypto"
)

type EntryType string

// These strings were selected to match the output of `keytool -list`
const (
	PrivateKeyEntry  EntryType = "PrivateKeyEntry"
	TrustedCertEntry EntryType = "trustedCertEntry"
	SecretKeyEntry   EntryType = "SecretKeyEntry"
)

const (
	CertTypeX509 = "X.509"
)

const (
	KeyFormatRaw   = "RAW"
	KeyFormatPKCS8 = "PKCS#8"
)

type Key struct {
	Algorithm algorithm.Algorithm
	Format    string
	Bytes     []byte
}

type Entry struct {
	Type         EntryType
	Alias        string
	Date         time.Time
	Certificates []Certificate
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

type Certificate struct {
	Type  string
	Bytes []byte
}

type PrivateKey struct {
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func (e Entry) ParseCertificates() ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	for _, cert := range e.Certificates {
		if cert.Type != CertTypeX509 {
			return nil, fmt.Errorf("unexpected certitifacte type: %s", cert.Type)
		}
		c, err := x509.ParseCertificate(cert.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func (e Entry) EncryptionAlgorithm() algorithm.Algorithm {
	if len(e.EncryptedKey.Bytes) == 0 {
		return algorithm.None
	}
	if e.EncryptedKey.SealAlg == "" {
		var k PrivateKey
		_, err := asn1.Unmarshal(e.EncryptedKey.Bytes, &k)
		if err != nil {
			return algorithm.Unknown
		}
		return algorithm.FromOID(k.Algo.Algorithm)
	}
	return algorithm.FromName(e.EncryptedKey.SealAlg)
}

func (e Entry) Decrypt(password string) (*Key, error) {
	k := e.EncryptedKey
	switch e.EncryptionAlgorithm().Name {
	case "":
		return nil, nil

	case algorithm.JDKKeyProtector.Name:
		var priv PrivateKey
		_, err := asn1.Unmarshal(k.Bytes, &priv)
		if err != nil {
			return nil, err
		}
		b := javaxcrypto.DecryptJKSEntry(priv.PrivateKey, javalang.String(password))
		var sk pkcs8
		_, err = asn1.Unmarshal(b, &sk)
		return &Key{
			Algorithm: algorithm.FromOID(sk.Algo.Algorithm),
			Format:    KeyFormatPKCS8,
			Bytes:     b,
		}, err

	case algorithm.JCEKeyProtector.Name:
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
			Algorithm: algorithm.FromOID(sk.Algo.Algorithm),
			Format:    KeyFormatPKCS8,
			Bytes:     b,
		}, err

	case algorithm.PBEWithMD5AndTripleDES.Name:
		plaintext := javaxcrypto.DecryptPBEWithMD5AndTripleDES(k.Bytes, javalang.String(password), k.CipherParams.Salt, k.CipherParams.Rounds)
		var sks secretKeySpec
		err := java.Unmarshal(plaintext, &sks)
		if err == nil {
			return &Key{
				Algorithm: algorithm.FromName(sks.Algorithm),
				Format:    KeyFormatRaw,
				Bytes:     sks.Key,
			}, nil
		}
		var kr keyRep
		err = java.Unmarshal(plaintext, &kr)
		if err == nil {
			return &Key{
				Algorithm: algorithm.FromName(kr.Algorithm),
				Format:    kr.Format,
				Bytes:     kr.Encoded,
			}, nil
		}
		return nil, err

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", e.EncryptionAlgorithm().Name)
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
