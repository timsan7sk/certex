package tests

import (
	"certex"
	"testing"
)

func TestEncrypt(t *testing.T) {
	pub, _ := generateKeyPairTest(t)
	data := "TEST_DATA_FOR_ENCRYPT"
	mech := certex.NewMechanism(certex.CKM_RSA_PKCS)

	if err := pub.EncryptInit(mech); err != nil {
		t.Fatal(err)
	}
	_, err := pub.Encrypt([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
}
