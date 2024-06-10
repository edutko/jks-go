package keystore

type keyRep struct {
	Algorithm string `java:"java.security.KeyRep.algorithm"`
	Encoded   []byte `java:"java.security.KeyRep.encoded"`
	Format    string `java:"java.security.KeyRep.format"`
	//Type      string `java:"java.security.KeyRep.type"`
}

type sealedObject struct {
	SealAlg          string `java:"javax.crypto.SealedObject.sealAlg"`
	ParamsAlg        string `java:"javax.crypto.SealedObject.paramsAlg"`
	EncryptedContent []byte `java:"javax.crypto.SealedObject.encryptedContent"`
	EncodedParams    []byte `java:"javax.crypto.SealedObject.encodedParams"`
}

type secretKeySpec struct {
	Algorithm string `java:"javax.crypto.spec.SecretKeySpec.algorithm"`
	Key       []byte `java:"javax.crypto.spec.SecretKeySpec.key"`
}
