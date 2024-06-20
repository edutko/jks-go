package keystore

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"

	javalang "github.com/edutko/cafegopher/java/lang"

	"github.com/edutko/jks-go/crypto/pkcs12"
)

var ErrBadMAC = errors.New("invalid MAC")

type KeystoreType string

const (
	KeystoreTypeUnknown KeystoreType = "unknown"
	KeystoreTypeJKS     KeystoreType = "JKS"
	KeystoreTypeJCEKS   KeystoreType = "JCEKS"
	KeystoreTypePKCS12  KeystoreType = "PKCS12"
)

var JKSMagic = []byte{0xFE, 0xED, 0xFE, 0xED}
var JCEKSMagic = []byte{0xCE, 0xCE, 0xCE, 0xCE}

var DefaultPasswords = []string{
	DefaultPasswordOracleCacerts,
	DefaultPasswordMacOSCacerts,
	DefaultPasswordWebSphere,
	DefaultPasswordJetty,
	"",
	"secret",
	"password",             // https://docs.progress.com/bundle/openedge-authentication-gateway-117/page/Change-the-keystore-password-utility-changeP12pwd.html
	"manage",               // https://tech.forums.softwareag.com/t/which-is-the-default-sag-keystore-password/206510
	"wso2carbon",           // https://medium.com/@randima.somathilaka/changing-default-keystore-passwords-in-wso2-api-manager-3-0-0-897b0918eb88
	"aircontrolenterprise", // https://community.ui.com/questions/Unifi-Controller-change-Password-of-the-keystore/e8b6e029-f5a9-4ebd-a009-93046f83a21c
	"TrCWebAS",             //https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0074500
}

const (
	DefaultPasswordJetty         = "storepwd"
	DefaultPasswordMacOSCacerts  = "changeme"
	DefaultPasswordOracleCacerts = "changeit" // https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html#terms
	DefaultPasswordTomcat        = "changeit" // https://tomcat.apache.org/tomcat-7.0-doc/ssl-howto.html
	DefaultPasswordWebSphere     = "WebAS"    // https://www.ibm.com/docs/en/was/9.0.5?topic=ssl-keystore-configurations
)

type Keystore struct {
	Format  KeystoreType
	Entries []KeystoreEntry
	MAC     []byte
}

func LoadFromFile(name, keystorePassword string) (*Keystore, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	return Parse(data, keystorePassword)
}

func Parse(data []byte, keystorePassword string) (*Keystore, error) {
	format := detectFormat(data)

	switch format {
	case KeystoreTypeJKS, KeystoreTypeJCEKS:
		k, err := InsecureParse(data)
		if err != nil {
			return nil, err
		}
		macOffset := len(data) - len(k.MAC)
		if ok := validateStoreMAC(data[:macOffset], javalang.String(keystorePassword), k.MAC); !ok {
			return nil, ErrBadMAC
		}
		return k, nil

	case KeystoreTypePKCS12:
		k := Keystore{Format: format}
		certs, err := pkcs12.DecodeTrustStore(data, keystorePassword)
		if err != nil {
			return nil, fmt.Errorf("pkcs12.DecodeTrustStore: %w", err)
		}
		for _, c := range certs {
			k.Entries = append(k.Entries, KeystoreEntry{
				Certificates: []*x509.Certificate{c},
			})
		}
		return &k, nil
	}

	return nil, fmt.Errorf("unknown keystore format")
}

func InsecureParse(data []byte) (*Keystore, error) {
	var k Keystore
	k.Format = detectFormat(data)

	switch k.Format {
	case KeystoreTypeJKS, KeystoreTypeJCEKS:
		r := bytes.NewReader(data)

		h, err := readJKSHeader(r)
		if err != nil {
			return nil, err
		}

		k.Entries, err = readJKSEntries(r, int(h.Length))
		if err != nil {
			return nil, err
		}

		k.MAC, err = readMAC(r)
		if err != nil {
			return nil, err
		}

		_, err = r.ReadByte()
		if err == nil || !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("possible corruption: unexpected data after MAC")
		}

	case KeystoreTypePKCS12:
		certs, err := pkcs12.DecodeTrustStore(data, "")
		if err != nil {
			return nil, fmt.Errorf("pkcs12.DecodeTrustStore: %w", err)
		}
		for _, c := range certs {
			k.Entries = append(k.Entries, KeystoreEntry{
				Type:         TrustedCertEntry,
				Certificates: []*x509.Certificate{c},
			})
		}
	}

	return &k, nil
}

func detectFormat(data []byte) KeystoreType {
	if bytes.Equal(data[:4], JKSMagic) {
		return KeystoreTypeJKS

	} else if bytes.Equal(data[:4], JCEKSMagic) {
		return KeystoreTypeJCEKS

	} else if pkcs12.MaybePKCS12(data) {
		return KeystoreTypePKCS12
	}

	return KeystoreTypeUnknown
}
