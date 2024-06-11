package crypto

import (
	"bytes"
	"crypto/sha1"

	javalang "github.com/edutko/cafegopher/java/lang"

	"github.com/edutko/jks-go/crypto/pkcs7"
)

func JavaKeystoreMAC(data []byte, keystorePassword javalang.String) []byte {
	// https://neilmadden.blog/2017/11/17/java-keystores-the-gory-details/
	h := sha1.New()
	h.Write(keystorePassword.ToUCS2Bytes())
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(data)
	return h.Sum(nil)
}

func DecryptJKSEntry(data []byte, keyPassword javalang.String) []byte {
	salt, ciphertext, tag := splitCiphertext(data)

	var h [sha1.Size]byte
	copy(h[:], salt)
	passwd := keyPassword.ToUCS2Bytes()

	var plaintext []byte
	for i := 0; i < len(ciphertext); i += sha1.Size {
		h = sha1.Sum(append(passwd, h[:]...))
		chunkSize := sha1.Size
		remaining := len(ciphertext) - i
		if chunkSize > remaining {
			chunkSize = remaining
		}
		block := xor(ciphertext[i:i+chunkSize], h[:])
		plaintext = append(plaintext, block...)
	}

	computedTag := sha1.Sum(append(passwd, plaintext...))
	if !bytes.Equal(computedTag[:], tag) {
		return nil
	}

	return pkcs7.Unpad(plaintext, 16)
}

func splitCiphertext(data []byte) (salt, ciphertext, tag []byte) {
	salt = data[:sha1.Size]
	tagOffset := len(data) - sha1.Size
	ciphertext = data[sha1.Size:tagOffset]
	tag = data[tagOffset:]
	return
}

func xor(a, b []byte) []byte {
	l := len(a)
	if l > len(b) {
		l = len(b)
	}
	for i := 0; i < l; i++ {
		a[i] = a[i] ^ b[i]
	}
	return a
}
