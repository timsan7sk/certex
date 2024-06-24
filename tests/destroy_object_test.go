package tests

import (
	"testing"
)

func TestDestroyObject(t *testing.T) {
	pub, priv := generateKeyPairTest(t)
	_ = pub.DestroyObject()
	_ = priv.DestroyObject()
}
