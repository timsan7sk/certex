package tests

import "testing"

func TestGetObjectSize(t *testing.T) {
	s := generateKeyTest(t)
	if _, err := s.GetObjectSize(); err != nil {
		t.Fatal(err)
	}
}
