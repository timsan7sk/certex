package tests

import (
	"certex"
	"testing"
)

func createObjectTest(t *testing.T) certex.Object {

	o, err := slot.CreateObject(dataAttrs)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestCreateObject(t *testing.T) {
	o := createObjectTest(t)
	err := o.DestroyObject()
	if err != nil {
		t.Fatal(err)
	}
}
