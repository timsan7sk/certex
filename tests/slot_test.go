package tests

import (
	"certex"
	"testing"
)

func newTestSlot(t *testing.T) *certex.Slot {
	m := NewTestOpen(t)
	opts := certex.SlotOptions{
		AdminPIN: testAdminPIN,
		PIN:      testPIN,
		Label:    testLabel,
	}
	if err := m.CreateSlot(7, opts); err != nil {
		t.Fatalf("createSlot(0, %v): %v", opts, err)
	}

	s, err := m.Slot(7, certex.Options{PIN: testPIN, ReadWrite: true})
	if err != nil {
		t.Fatalf("Slot(7): %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Closing slot: %v", err)
		}
	})
	return s
}

func TestNewSlot(t *testing.T) {
	newTestSlot(t)
}
