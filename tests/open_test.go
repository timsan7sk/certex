package tests

import (
	"certex"
	"fmt"
	"testing"
)

func newTestOpen(t *testing.T) *certex.Cryptoki {
	mod, err := certex.Open()
	t.Logf("Module: %+v", mod)
	if err != nil {
		fmt.Printf("Open: %s\n", err)
	}
	return mod
}
func TestOpen(t *testing.T) {
	newTestOpen(t)
}
