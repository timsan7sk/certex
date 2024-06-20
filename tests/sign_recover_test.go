package tests

import (
	"encoding/base64"
	"testing"
)

func signRecoverTest(t *testing.T, d string) string {
	var s string
	objs := findObjectsTest(t, fPrivKey)
	for _, o := range objs {
		if l, _ := o.Label(); l == testLabel1 {
			d, _ := base64.StdEncoding.DecodeString(d)
			if err := o.SignRecoverInit(&srMech); err != nil {
				t.Fatal(err)
			} else {
				if d, err := o.SignRecover(d); err != nil {
					t.Fatal(err)
				} else {
					s = base64.StdEncoding.EncodeToString(d)
				}
			}
		}
	}
	return s
}

func TestSignRecover(t *testing.T) {
	d := digestTest(t)
	signRecoverTest(t, d)
}
