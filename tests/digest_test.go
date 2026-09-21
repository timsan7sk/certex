package tests

import (
	"encoding/base64"
	"math/rand/v2"
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

func BenchmarkDigest(b *testing.B) {
	var d []byte
	for b.Loop() {
		r := make([]byte, rand.UintN(64)+1)
		if err := testPrivKey.DigestInit(mechDigSHA); err != nil {
			b.Fatal(err)
		} else {
			if d, err = testPrivKey.Digest(r); err != nil {
				b.Fatal(err)
			}
		}
		b64 := base64.StdEncoding.EncodeToString(d)
		b.Logf("Hashed Data: %s Len: %d", d, len(d))
		b.Logf("Hashed Base64: %s Len: %d", b64, len(b64))

	}
}
