package tests

import "testing"

func TestSetPin(t *testing.T) {
	if err := slot.SetPIN(testPIN, "00000000"); err != nil {
		t.Fatal(err)
	}
	if err := slot.SetPIN("00000000", testPIN); err != nil {
		t.Fatal(err)
	}
}
