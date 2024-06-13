package tests

import (
	"testing"
)

func TestMechanisms(t *testing.T) {
	if ml, err := mod.GetMechanismList(testSlotID); err != nil {
		t.Fatal(err)
	} else {
		for _, m := range ml {
			if _, err := mod.GetMechanismInfo(testSlotID, m); err != nil {
				t.Fatal(err)
			}
		}
	}
}
