package tests

import (
	"testing"
)

func verifyRecoverTest(t *testing.T, s []byte) []byte {
	var v []byte
	if err := testPubKey.VerifyRecoverInit(mechSigGOST); err != nil {
		t.Fatal(err)
	} else {
		if r, err := testPubKey.VerifyRecover(s); err != nil {
			t.Fatal(err)
		} else {
			v = r
		}
	}
	return v
}

func TestVerifyRecover(t *testing.T) {
	d := digestTest(t)
	s := signRecoverTest(t, d)
	_ = verifyRecoverTest(t, s)
}
