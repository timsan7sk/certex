package tests

import (
	"testing"
)

func digestTest(t *testing.T) []byte {
	var d []byte
	pub, priv := generateKeyPairTest(t)
	if err := priv.DigestInit(mechDigGOST); err != nil {
		t.Fatal(err)
	} else {
		if d, err = priv.Digest(testData); err != nil {
			t.Fatal(err)
		}
	}
	_ = pub.DestroyObject()
	_ = priv.DestroyObject()
	return d
}

func digestUpdateTest(t *testing.T) []byte {
	var d []byte
	pub, priv := generateKeyPairTest(t)
	if err := priv.DigestInit(mechDigGOST); err != nil {
		t.Fatal(err)
	} else {
		for i := 0; i < 3; i++ {
			if err := priv.DigestUpdate(testData); err != nil {
				t.Fatal(err)
			}
		}
		if c, err := priv.DigestFinal(); err != nil {
			t.Fatal(err)
		} else {
			d = c
		}
	}
	_ = pub.DestroyObject()
	_ = priv.DestroyObject()
	return d
}
func TestDigest(t *testing.T) {
	_ = digestTest(t)
}
func TestDigestUpdate(t *testing.T) {
	_ = digestUpdateTest(t)
}
