package tests

import (
	"testing"
)

func signRecoverTest(t *testing.T, d []byte) []byte {
	var s []byte
	pub, priv := generateKeyPairTest(t)

	if err := priv.SignRecoverInit(mechSigGOST); err != nil {
		t.Fatal(err)
	} else {
		if c, err := priv.SignRecover(d); err != nil {
			t.Fatal(err)
		} else {
			s = c
		}
	}
	_ = pub.DestroyObject()
	_ = priv.DestroyObject()
	return s
}

func TestSignRecover(t *testing.T) {
	d := digestTest(t)
	signRecoverTest(t, d)
}
