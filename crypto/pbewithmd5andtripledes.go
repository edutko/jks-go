package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"

	javalang "github.com/edutko/cafegopher/java/lang"
)

func DecryptPBEWithMD5AndTripleDES(ciphertext []byte, keyPassword javalang.String, salt []byte, iterations int) []byte {
	key, iv := pbkdfMD5(keyPassword, salt, iterations)

	b, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil
	}
	c := cipher.NewCBCDecrypter(b, iv)

	plaintext := make([]byte, len(ciphertext))
	c.CryptBlocks(plaintext, ciphertext)

	return plaintext
}

func pbkdfMD5(password javalang.String, salt []byte, iterations int) ([]byte, []byte) {
	// https://stackoverflow.com/q/65308500
	var h0 [md5.Size]byte
	copy(h0[:], salt[:4])

	var h1 [md5.Size]byte
	if bytes.Equal(salt[:4], salt[4:]) {
		for i := range salt[4:] {
			h1[i] = salt[8-i]
		}
	} else {
		copy(h1[:], salt[4:])
	}

	passwd := []byte(password)

	h0 = md5.Sum(append(h0[:4], passwd...))
	for i := 1; i < iterations; i++ {
		h0 = md5.Sum(append(h0[:], passwd...))
	}

	h1 = md5.Sum(append(h1[:4], passwd...))
	for i := 1; i < iterations; i++ {
		h1 = md5.Sum(append(h1[:], passwd...))
	}

	return append(h0[:], h1[:8]...), h1[8:]
}
