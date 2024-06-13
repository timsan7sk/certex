package tests

import "testing"

func TestGenerateRandom(t *testing.T) {
	_, err := slot.GenerateRandom(8)
	if err != nil {
		t.Fatal(err)
	}

}
