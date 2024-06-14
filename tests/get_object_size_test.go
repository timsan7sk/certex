package tests

import "testing"

func TestGetObjectSize(t *testing.T) {
	o, err := slot.FindObjects(fPubKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range o {
		if _, err := v.GetObjectSize(); err != nil {
			t.Fatal(err)
		}
	}
}
