package tests

import (
	"certex"
	"encoding/base64"
	"testing"
)

var mech = certex.Mechanism{
	Mechanism: certex.MechanismMap["CKM_CERTEX_GOSTR3411_2012_64"],
	Parameter: nil,
}

func DigestTest(t *testing.T) string {
	var s string
	objs := FindObjectsTest(t)

	for _, o := range objs {
		l, _ := o.Label()
		if l == "NUC_TEST_GOST_2015" {
			d, _ := base64.StdEncoding.DecodeString("RSPRqNtPvrjBwUMWgTUUqfkz2bMXrYB3akNQMwQdSRNUunhugNAnBzjZBg6HUh2TxjbPf7rbqTFrLU2bjC9An9NScz60qcDU7TQnDYUu1i0GPrVawCvHhfpziE2UJ3Bi")
			if err := o.DigestInit(&mech); err != nil {
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

func TestDigest(t *testing.T) {
	DigestTest(t)
}
