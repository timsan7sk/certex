package tests

import (
	"testing"
)

func TestCopyObject(t *testing.T) {
	o := createObjectTest(t)
	copy, err := o.CopyObject(copyAttrs)
	if err != nil {
		t.Fatal(err)
	}
	_ = copy.DestroyObject()
	_ = o.DestroyObject()
}
