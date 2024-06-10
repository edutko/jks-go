package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecryptJKSEntry(t *testing.T) {
	ciphertext, _ := hex.DecodeString("56f1174687744de7c2ce56373612eb0fb6851be121646cd6505038002a96668dbd6f44263d6121afd7ff619a07a3827b4c353c1b7f010bb236bec2fca4d4ae9555ee389e25ca1842020ad58ce53e995d75c78241c25fa96b01bb505107b15ded70f4dff1c38df0e36c0b51")
	expected, _ := hex.DecodeString("3041020100301306072a8648ce3d020106082a8648ce3d0301070427302502010104203a7cdd411d2aacc62d8dc75103c3ca3928ad2bbdb53a1002bdc4d7895c9774e9")

	plaintext := DecryptJKSEntry(ciphertext, "hunter2")

	assert.Equal(t, expected, plaintext)
}

func Test_xor(t *testing.T) {
	testCases := []struct {
		a, b, c string
	}{
		{"", "", ""},
		{"00", "00", "00"},
		{"ff", "00", "ff"},
		{"ff", "ff", "00"},
		{"000102030405060708090a0b0c0d0e0f", "00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f"},
		{"77697468206d7920726167746f702064", "726964696e6720696e206d7920352e30", "050010014e0a59491c410a0d4f450e54"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s XOR %s", tc.a, tc.b), func(t *testing.T) {
			a, _ := hex.DecodeString(tc.a)
			b, _ := hex.DecodeString(tc.b)
			expected, _ := hex.DecodeString(tc.c)

			actual := xor(a, b)

			assert.Equal(t, expected, actual)
		})
	}
}
