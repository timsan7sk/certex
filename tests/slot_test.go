package tests

import (
	"testing"
)

func TestGetSlotList(t *testing.T) {
	if _, err := mod.GetSlotList(); err != nil {
		t.Fatal(err)
	}
}

func TestGetSlotInfo(t *testing.T) {
	if _, err := slot.GetSlotInfo(); err != nil {
		t.Fatal(err)
	}
}
func TestGetSessionInfo(t *testing.T) {
	if _, err := slot.GetSessionInfo(); err != nil {
		t.Fatal(err)
	}
}
