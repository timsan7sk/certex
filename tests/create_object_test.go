package tests

import (
	"testing"

	"github.com/timsan7sk/certex"
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
	if err := o.DestroyObject(); err != nil {
		t.Fatal(err)
	}
}
