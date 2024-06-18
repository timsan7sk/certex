package tests

import (
	"certex"
	"encoding/base64"
	"testing"
)

var digMech = certex.Mechanism{
	Mechanism: certex.Mechanisms["CKM_CERTEX_GOSTR3411_2012_64"],
	Parameter: nil,
}

func digestTest(t *testing.T) string {
	var s string
	objs := findObjectsTest(t, fPrivKey)
	for _, o := range objs {
		l, _ := o.Label()
		if l == "NUC_TEST_GOST_2015" {
			d, _ := base64.StdEncoding.DecodeString("TEST_DATA_FOR_DIGEST")
			if err := o.DigestInit(&digMech); err != nil {
				t.Fatal(err)
			} else {
				if d, err := o.Digest(d); err != nil {
					t.Fatal(err)
				} else {
					s = base64.StdEncoding.EncodeToString(d)
				}
			}
		}
	}
	return s
}

func digestUpdateTest(t *testing.T) string {
	var s string
	objs := findObjectsTest(t, fPrivKey)
	for _, o := range objs {
		l, _ := o.Label()
		if l == "NUC_TEST_GOST_2015" {
			if err := o.DigestInit(&digMech); err != nil {
				t.Fatal(err)
			} else {
				d, _ := base64.StdEncoding.DecodeString("TEST_DATA_FOR_DIGEST")
				for i := 0; i < 3; i++ {
					if err := o.DigestUpdate(d); err != nil {
						t.Fatal(err)
					}
				}
				if c, err := o.DigestFinal(); err != nil {
					t.Fatal(err)
				} else {
					s = base64.StdEncoding.EncodeToString(c)
				}
			}
		}
	}
	return s
}
func TestDigest(t *testing.T) {
	digestTest(t)
}
func TestDigestUpdate(t *testing.T) {
	digestUpdateTest(t)
}
