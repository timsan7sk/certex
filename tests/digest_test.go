package tests

import (
	"encoding/base64"
	"testing"
)

func digestTest(t *testing.T) string {
	var s string
	objs := findObjectsTest(t, fPrivKey)
	for _, o := range objs {
		if l, _ := o.Label(); l == testLabel0 {
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
		if l, _ := o.Label(); l == testLabel0 {
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
