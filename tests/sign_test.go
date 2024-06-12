package tests

import (
	"certex"
	"encoding/base64"
	"testing"
)

func signTest(t *testing.T) string {
	var mech = certex.Mechanism{
		Mechanism: certex.MechanismMap["CKM_CERTEX_GOSTR3410_2015"],
		Parameter: nil,
	}
	var s string
	d := digestTest(t)
	objs := findObjectsTest(t, fPrivKey)
	for _, o := range objs {
		l, _ := o.Label()
		if l == "NUC_TEST_GOST_2015" {
			d, _ := base64.StdEncoding.DecodeString(d)
			if err := o.SignInit(&mech); err != nil {
				t.Fatal(err)
			} else {
				if d, err := o.Sign(d); err != nil {
					t.Fatal(err)
				} else {
					s = base64.StdEncoding.EncodeToString(d)
				}
			}
		}
	}
	return s
}

func TestSign(t *testing.T) {
	signTest(t)
}
