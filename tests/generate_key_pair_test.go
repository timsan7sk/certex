package tests

import (
	"testing"

	"github.com/timsan7sk/certex"
)

func generateKeyPairTest(t *testing.T) (certex.Object, certex.Object) {

	pubKey, privKey, err := slot.GenerateKeyPair(mechPairGenGOST, pubKeyAttrs, privKeyAttrs)
	if err != nil {
		t.Fatal(err)
	}
	return pubKey, privKey
}
func TestGenerateKeyPair(t *testing.T) {
	pub, priv := generateKeyPairTest(t)
	_ = pub.DestroyObject()
	_ = priv.DestroyObject()
}
