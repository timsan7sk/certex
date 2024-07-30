package tests

import (
	"testing"
)

func verifyTest(t *testing.T, d, s []byte) {
	if err := testPubKey.VerifyInit(mechSigGOST); err != nil {
		t.Fatal(err)
	} else {
		if err := testPubKey.Verify(d, s); err != nil {
			t.Fatal(err)
		}
	}
}
func TestVerify(t *testing.T) {
	d := digestTest(t)
	s := signTest(t, d)
	verifyTest(t, d, s)
}
