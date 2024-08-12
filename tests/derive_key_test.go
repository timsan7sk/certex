package tests

import (
	"testing"
)

func TestDeriveKey(t *testing.T) {
	_, err := testPrivKey.DeriveKey(mechSigGOST, privKeyAttrs)
	if err != nil {
		t.Fatal(err)
	}
}
