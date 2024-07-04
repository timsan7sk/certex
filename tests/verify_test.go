package tests

import (
	"testing"
)

func verifyTest(t *testing.T, d, s []byte) {
	objs := findObjectsTest(t, fPubKey)
	for _, o := range objs {
		if l, _ := o.Label(); l == testLabel0 {
			if err := o.VerifyInit(mechSigGOST); err != nil {
				t.Fatal(err)
			} else {
				if err := o.Verify(d, s); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
func TestVerify(t *testing.T) {
	d := digestTest(t)
	s := signTest(t, d)
	verifyTest(t, d, s)
}
