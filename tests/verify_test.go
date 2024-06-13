package tests

import (
	"encoding/base64"
	"testing"
)

func verifyTest(t *testing.T, d string, s string) {
	objs := findObjectsTest(t, fPubKey)
	for _, o := range objs {
		l, _ := o.Label()
		if l == "NUC_TEST_GOST_2015" {
			d, _ := base64.StdEncoding.DecodeString(d)
			s, _ := base64.StdEncoding.DecodeString(s)
			if err := o.VerifyInit(&sigMech); err != nil {
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
