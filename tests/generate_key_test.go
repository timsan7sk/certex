package tests

import (
	"certex"
	"testing"
)

func generateKeyTest(t *testing.T) certex.Object {
	key, err := slot.GenerateKey(mechKeyGenAES, secKeyAttrs)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestGenerateKeyTest(t *testing.T) {
	key := generateKeyTest(t)
	err := key.DestroyObject()
	if err != nil {
		t.Fatal(err)
	}
}
