package tests

import (
	"certex"
	"testing"
)

func generateKeyPairTest(t *testing.T) (certex.Object, certex.Object) {
	public := []*certex.Attribute{
		certex.NewAttribute(certex.CKA_CLASS, certex.CKO_PUBLIC_KEY),
		certex.NewAttribute(certex.CKA_KEY_TYPE, certex.CKK_RSA),
		certex.NewAttribute(certex.CKA_TOKEN, false),
		certex.NewAttribute(certex.CKA_VERIFY, true),
		certex.NewAttribute(certex.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		certex.NewAttribute(certex.CKA_MODULUS_BITS, 2048),
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_RSA_TEST_KEY"),
	}
	private := []*certex.Attribute{
		certex.NewAttribute(certex.CKA_TOKEN, false),
		certex.NewAttribute(certex.CKA_SIGN, true),
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_RSA_TEST_KEY"),
		certex.NewAttribute(certex.CKA_SENSITIVE, true),
		certex.NewAttribute(certex.CKA_EXTRACTABLE, true),
	}
	mech := certex.NewMechanism(certex.CKM_RSA_PKCS_KEY_PAIR_GEN)
	pubKey, privKey, err := slot.GenerateKeyPair(mech, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return pubKey, privKey
}
func TestGenerateKeyPair(t *testing.T) {
	pub, priv := generateKeyPairTest(t)
	_ = pub.DestroyObject()
	_ = priv.DestroyObject()
}
