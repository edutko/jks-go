package jetty

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeobfuscate(t *testing.T) {
	testCases := []struct {
		obfuscated string
		expected   string
	}{
		{"OBF:1vn21ugu1saj1v9i1v941sar1ugw1vo0", "changeit"},
		{"OBF:1vny1zlo1x8e1vnw1vn61x8g1zlu1vn4", "storepwd"},
		{"OBF:1u2u1wml1z7s1z7a1wnl1u2g", "keypwd"},
	}

	for _, tc := range testCases {
		t.Run(tc.obfuscated, func(t *testing.T) {
			actual := Deobfuscate(tc.obfuscated)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
