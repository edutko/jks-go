package pkcs7

func Unpad(plaintext []byte, blockSize int) []byte {
	lastByte := plaintext[len(plaintext)-1]
	paddingLength := int(lastByte)

	if paddingLength <= blockSize && len(plaintext) > paddingLength {
		end := len(plaintext) - paddingLength
		for i := end; i < len(plaintext); i++ {
			if plaintext[i] != lastByte {
				return plaintext
			}
		}
		return plaintext[:end]
	}

	return plaintext
}
