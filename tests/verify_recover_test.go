package tests

import (
	"encoding/base64"
	"testing"
)

func verifyRecoverTest(t *testing.T, s string) string {
	var r []byte
	objs := findObjectsTest(t, fPubKey)
	for _, o := range objs {
		if l, _ := o.Label(); l == testLabel1 {
			s, _ := base64.StdEncoding.DecodeString(s)

			if err := o.VerifyRecoverInit(&srMech); err != nil {
				t.Fatal(err)
			} else {
				if r, err = o.VerifyRecover(s); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return base64.RawStdEncoding.EncodeToString(r)
}

func TestVerifyRecover(t *testing.T) {
	d := digestTest(t)
	s := signRecoverTest(t, d)
	_ = verifyRecoverTest(t, s)
}
