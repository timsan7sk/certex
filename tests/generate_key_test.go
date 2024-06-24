package tests

import (
	"certex"
	"testing"
)

func generateKeyTest(t *testing.T) certex.Object {
	keyTemplate := []*certex.Attribute{
		certex.NewAttribute(certex.CKA_TOKEN, false),
		certex.NewAttribute(certex.CKA_ENCRYPT, true),
		certex.NewAttribute(certex.CKA_DECRYPT, true),
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_AES_TEST_KEY"),
		certex.NewAttribute(certex.CKA_SENSITIVE, true),
		certex.NewAttribute(certex.CKA_EXTRACTABLE, true),
		certex.NewAttribute(certex.CKA_VALUE_LEN, 16),
	}
	mech := certex.NewMechanism(certex.CKM_AES_KEY_GEN)
	key, err := slot.GenerateKey(mech, keyTemplate)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestGenerateKeyTest(t *testing.T) {
	key := generateKeyTest(t)
	err := key.DestroyObject()
	if err != nil {
		t.Fatal(err)
	}
}
