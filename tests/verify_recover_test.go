package tests

import (
	"testing"
)

func verifyRecoverTest(t *testing.T, s []byte) []byte {
	var v []byte
	pub, priv := generateKeyPairTest(t)
	if err := pub.VerifyRecoverInit(mechSigGOST); err != nil {
		t.Fatal(err)
	} else {
		if r, err := pub.VerifyRecover(s); err != nil {
			t.Fatal(err)
		} else {
			v = r
		}
	}
	_ = pub.DestroyObject()
	_ = priv.DestroyObject()
	return v
}

func TestVerifyRecover(t *testing.T) {
	d := digestTest(t)
	s := signRecoverTest(t, d)
	_ = verifyRecoverTest(t, s)
}
