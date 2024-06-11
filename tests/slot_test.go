package tests

import (
	"certex"
	"testing"
)

func SlotTest(t *testing.T) *certex.Slot {
	m := NewTestOpen(t)
	opts := certex.Options{
		PIN:       "25032016",
		ReadWrite: false,
	}
	s, err := m.Slot(uint32(0), opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestSlot(t *testing.T) {
	SlotTest(t)
}

// func createTestSlot(t *testing.T) *certex.Slot {
// 	m := NewTestOpen(t)
// 	opts := certex.SlotOptions{
// 		AdminPIN: testAdminPIN,
// 		PIN:      testPIN,
// 		Label:    testLabel,
// 	}
// 	if err := m.CreateSlot(0, opts); err != nil {
// 		t.Fatalf("createSlot(0, %v): %v", opts, err)
// 	}

// 	s, err := m.Slot(0, certex.Options{PIN: testPIN, ReadWrite: true})
// 	if err != nil {
// 		t.Fatalf("Slot(0): %v", err)
// 	}
// 	t.Cleanup(func() {
// 		if err := s.Close(); err != nil {
// 			t.Errorf("Closing slot: %v", err)
// 		}
// 	})
// 	return s
// }

// func TestCreateSlot(t *testing.T) {
// 	createTestSlot(t)
// }
