package tests

import (
	"certex"
	"testing"
)

var fltr = certex.Filter{
	Class: certex.ClassPrivateKey,
	Label: "",
}

func FindObjectsTest(t *testing.T) []certex.Object {
	s := SlotTest(t)

	o, err := s.FindObjects(fltr)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func TestFindObjects(t *testing.T) {
	FindObjectsTest(t)
}
