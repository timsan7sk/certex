package tests

import (
	"certex"
	"testing"
)

var fltr = certex.Filter{
	Class: certex.ClassPrivateKey,
	Label: "",
}

func findObjectsTest(t *testing.T) []certex.Object {
	o, err := slot.FindObjects(fltr)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func TestFindObjects(t *testing.T) {
	findObjectsTest(t)
}
