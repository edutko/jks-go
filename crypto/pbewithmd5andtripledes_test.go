package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecryptPBEWithMD5AndTripleDES(t *testing.T) {
	ciphertext, _ := hex.DecodeString("3f8bcb2673101d9dbddcedce8f3e34de7ca8784218c3418cc5184b416179dac37dcfeffa7219ef04d429f099ce765a69e928110e17f51b02e62549f85d1882129ca466525316fe9dbfe1b6af77858d17d79d3a2f08f5ffd8182ca7b43e92f2eb2ff640248738ece55a3b6c92060b890a8c500b9086d394c485082ff6e1dcde3c80e49f122dbcf65be705aed7b77fd52e22d13414f251ae6dc7ba22afac6fcdac5a7eb4966dd5c21718fb7b5fe6b65bbba9ec48ff5b49e0c4324a7391a245ee1b792451e726f6b1031e9ace0db1888a7d37449caf7c9c3098e531b373aad422c51f5b28be32e72d200719964b59c4f22a30a4c1ec9d1cb98aebf6ea27526ba57655dbac3d2b5419b2a8cfc43d387515e1a0889b20c66f3db0")
	salt, _ := hex.DecodeString("bbbb520459a91c99")
	expected, _ := hex.DecodeString("aced0005737200146a6176612e73656375726974792e4b6579526570bdf94fb3889aa5430200044c0009616c676f726974686d7400124c6a6176612f6c616e672f537472696e673b5b0007656e636f6465647400025b424c0006666f726d617471007e00014c00047479706574001b4c6a6176612f73656375726974792f4b657952657024547970653b7870740010504245576974684d4435416e64444553757200025b42acf317f8060854e00200007870000000096d6f6e6b65793132337400035241577e7200196a6176612e73656375726974792e4b6579526570245479706500000000000000001200007872000e6a6176612e6c616e672e456e756d00000000000000001200007870740006534543524554")

	plaintext := DecryptPBEWithMD5AndTripleDES(ciphertext, "hunter2", salt, 200_000)

	assert.Equal(t, expected, plaintext)
}
