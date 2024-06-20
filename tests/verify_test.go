package tests

import (
	"encoding/base64"
	"testing"
)

func verifyTest(t *testing.T, d string, s string) {
	objs := findObjectsTest(t, fPubKey)
	for _, o := range objs {
		if l, _ := o.Label(); l == testLabel0 {
			d, _ := base64.StdEncoding.DecodeString(d)
			s, _ := base64.StdEncoding.DecodeString(s)
			if err := o.VerifyInit(&sMech); err != nil {
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
