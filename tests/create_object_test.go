package tests

import (
	"certex"
	"testing"
)

func TestCreateObject(t *testing.T) {
	attrs := []*certex.Attribute{
		certex.NewAttribute(certex.CKA_CLASS, certex.CKO_DATA),
		certex.NewAttribute(certex.CKA_TOKEN, false),
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_TEST_DATA_OBJECT"),
		certex.NewAttribute(certex.CKA_APPLICATION, "TIMSAN_TEST_AN_APPLICATION"),
		certex.NewAttribute(certex.CKA_VALUE, "TIMSAN_TEST_VALUE_DATA"),
	}
	o, err := slot.CreateObject(attrs)
	if err != nil {
		t.Fatal(err)
	}
	err = o.DestroyObject()
	if err != nil {
		t.Fatal(err)
	}
}
