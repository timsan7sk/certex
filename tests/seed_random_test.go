package tests

import (
	"testing"
)

func TestSeedRandom(t *testing.T) {
	seed := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := slot.SeedRandom(seed); err != nil {
		t.Fatal(err)
	}
}
