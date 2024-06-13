package tests

import (
	"certex"
	"encoding/base64"
	"testing"
)

var sigMech = certex.Mechanism{
	Mechanism: certex.Mechanisms["CKM_CERTEX_GOSTR3410_2015"],
	Parameter: nil,
}

func signTest(t *testing.T, d string) string {
	var s string
	objs := findObjectsTest(t, fPrivKey)
	for _, o := range objs {
		l, _ := o.Label()
		if l == "NUC_TEST_GOST_2015" {
			d, _ := base64.StdEncoding.DecodeString(d)
			if err := o.SignInit(&sigMech); err != nil {
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
	d := digestTest(t)
	signTest(t, d)
}
