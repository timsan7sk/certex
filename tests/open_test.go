package tests

import (
	"certex"
	"testing"
)

func NewTestOpen(t *testing.T) *certex.Cryptoki {
	m, err := certex.Open("libcertex-rcsp_r.so.1")
	if err != nil {
		t.Fatalf("Open: %s\n", err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("Close: %s", err)
		}
	})
	return m
}
func TestOpen(t *testing.T) {
	NewTestOpen(t)
}
