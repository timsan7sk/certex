package tests

import (
	"testing"
)

func signTest(t *testing.T, d []byte) []byte {
	var s []byte
	if err := testPrivKey.SignInit(mechSigGOST); err != nil {
		t.Fatal(err)
	} else {
		if c, err := testPrivKey.Sign(d); err != nil {
			t.Fatal(err)
		} else {
			s = c
		}
	}
	return s
}
func signUpdateTest(t *testing.T, d []byte) []byte {
	var s []byte
	pub, priv := generateKeyPairTest(t)
	if err := priv.SignInit(mechSigGOST); err != nil {
		t.Fatal(err)
	} else {
		for i := 0; i < 3; i++ {
			if err := priv.SignUpdate(d); err != nil {
				t.Fatal(err)
			}
		}
		if c, err := priv.SignFinal(); err != nil {
			t.Fatal(err)
		} else {
			s = c
		}
	}
	_ = pub.DestroyObject()
	_ = priv.DestroyObject()
	return s
}
func TestSign(t *testing.T) {
	d := digestTest(t)
	signTest(t, d)
}
func TestSignUpdate(t *testing.T) {
	d := digestUpdateTest(t)
	signUpdateTest(t, d)
}
