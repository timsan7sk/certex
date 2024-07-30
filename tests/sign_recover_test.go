package tests

import (
	"testing"
)

func signRecoverTest(t *testing.T, d []byte) []byte {
	var s []byte

	if err := testPrivKey.SignRecoverInit(mechSigGOST); err != nil {
		t.Fatal(err)
	} else {
		if c, err := testPrivKey.SignRecover(d); err != nil {
			t.Fatal(err)
		} else {
			s = c
		}
	}
	return s
}

func TestSignRecover(t *testing.T) {
	d := digestTest(t)
	signRecoverTest(t, d)
}
