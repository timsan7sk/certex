package tests

import (
	"fmt"
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
	if s, err := slot.GetSessionInfo(); err != nil {
		t.Fatal(err)
	} else {
		fmt.Printf("%+v\n", s)
	}
}
