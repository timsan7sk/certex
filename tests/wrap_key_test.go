package tests

import (
	"testing"
)

func wrapKeyTest(t *testing.T) []byte {
	w, err := testPrivKey.WrapKey(mechSigGOST, testPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWrapKey(t *testing.T) {
	_ = wrapKeyTest(t)
}
