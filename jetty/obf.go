package jetty

import (
	"strconv"
	"strings"
)

const ObfuscationPrefix = "OBF:"

func Deobfuscate(s string) string {
	// https://github.com/jetty/jetty.project/blob/45562b012ad19c28c1eb6b8efeb9a7c9f59dfcec/jetty-core/jetty-util/src/main/java/org/eclipse/jetty/util/security/Password.java#L166
	s = strings.TrimPrefix(s, ObfuscationPrefix)

	b := make([]byte, len(s)/2)
	l := 0
	for i := 0; i < len(s); i += 4 {
		if s[i] == 'U' {
			i++
			i0, err := strconv.ParseInt(s[i:i+4], 36, 24)
			if err != nil {
				panic(err)
			}
			b[l] = byte(i0 >> 8)
			l++
		} else {
			i0, err := strconv.ParseInt(s[i:i+4], 36, 24)
			if err != nil {
				panic(err)
			}
			i1 := i0 / 256
			i2 := i0 % 256
			b[l] = byte((i1 + i2 - 254) / 2)
			l++
		}
	}

	return strings.TrimRight(string(b), "\x00")
}
