package tests

import (
	"testing"
)

func TestDestroyObject(t *testing.T) {
	_, _ = generateKeyPair(t)
	pubObjs := findObjectsTest(t, fPubKey)
	for _, o := range pubObjs {
		l, _ := o.Label()
		if l == "TIMSAN_RSA_TEST_KEY" {
			o.DestroyObject()
		}
	}
	privObjs := findObjectsTest(t, fPrivKey)
	for _, o := range privObjs {
		l, _ := o.Label()
		if l == "TIMSAN_RSA_TEST_KEY" {
			o.DestroyObject()
		}
	}
}
