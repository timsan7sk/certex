package tests

import (
	"testing"

	"pki.gov.kz/go/certex"
)

func TestEncrypt(t *testing.T) {
	data := "TEST_DATA_FOR_ENCRYPT"
	mech := certex.NewMechanism(certex.CKM_CERTEX_GOSTR3410_2012)

	if err := testPubKey.EncryptInit(mech); err != nil {
		t.Fatal(err)
	}
	_, err := testPubKey.Encrypt([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
}
