package tests

import (
	"testing"
)

func digestTest(t *testing.T) (d []byte) {
	if err := testPrivKey.DigestInit(mechDigGOST); err != nil {
		t.Fatal(err)
	} else {
		if d, err = testPrivKey.Digest(testData); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func digestUpdateTest(t *testing.T) (d []byte) {
	if err := testPrivKey.DigestInit(mechDigGOST); err != nil {
		t.Fatal(err)
	} else {
		for i := 0; i < 3; i++ {
			if err := testPrivKey.DigestUpdate(testData); err != nil {
				t.Fatal(err)
			}
		}
		if c, err := testPrivKey.DigestFinal(); err != nil {
			t.Fatal(err)
		} else {
			d = c
		}
	}
	return d
}
func TestDigest(t *testing.T) {
	_ = digestTest(t)
}
func TestDigestUpdate(t *testing.T) {
	_ = digestUpdateTest(t)
}
