package tests

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func signTest(t *testing.T, d string) string {
	var s string
	objs := findObjectsTest(t, fPrivKey)
	for _, o := range objs {
		l, _ := o.Label()
		if l == testLabel0 {
			d, _ := base64.StdEncoding.DecodeString(d)
			if err := o.SignInit(&sMech); err != nil {
				t.Fatal(err)
			} else {
				if d, err := o.Sign(d); err != nil {
					t.Fatal(err)
				} else {
					s = base64.StdEncoding.EncodeToString(d)
				}
			}
		}
	}
	return s
}
func signUpdateTest(t *testing.T, d string) string {
	var s string
	objs := findObjectsTest(t, fPrivKey)
	for _, o := range objs {
		if l, _ := o.Label(); l == testLabel0 {
			if err := o.SignInit(&suMech); err != nil {
				t.Fatal(err)
			} else {
				d, _ := base64.StdEncoding.DecodeString(d)
				if err := o.SignUpdate(d); err != nil {
					t.Fatal(err)
				}
			}
			if b, err := o.SignFinal(); err != nil {
				t.Fatal(err)
			} else {
				s = base64.StdEncoding.EncodeToString(b)
			}

		}
	}
	fmt.Printf("s: %s", s)
	return s
}
func TestSign(t *testing.T) {
	d := digestTest(t)
	signTest(t, d)
}
func TestSignUpdate(t *testing.T) {
	d := digestUpdateTest(t)
	signUpdateTest(t, d)
}
