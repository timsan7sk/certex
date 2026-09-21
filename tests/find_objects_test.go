package tests

import (
	"testing"

	"github.com/timsan7sk/certex"
)

var fPrivKey = certex.Filter{
	Class: certex.ClassPrivateKey,
	Label: "TIMSAN_RSA_TEST_KEY_LABEL",
}

var fPubKey = certex.Filter{
	Class: certex.ClassPublicKey,
	// Label: "NUC_TEST_GOST_2015",
	Label: "TIMSAN_RSA_TEST_KEY_LABEL",
}

//	var fSecKey = certex.Filter{
//		Class: certex.ClassSecretKey,
//		Label: "",
//	}
var fCert = certex.Filter{
	Class: certex.ClassCertificate,
	Label: "",
}

func findObjectsTest(t *testing.T, f certex.Filter) []certex.Object {
	o, err := slot.FindObjects(f)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func TestFindObjects(t *testing.T) {
	// attrs := []*certex.Attribute{
	// 	// certex.NewAttribute(certex.CKA_CLASS, certex.CKO_PUBLIC_KEY),
	// 	// certex.NewAttribute(certex.CKA_KEY_TYPE, certex.CKK_GOSTR3411),
	// 	certex.NewAttribute(certex.CKA_PUBLIC_EXPONENT, nil),
	// 	certex.NewAttribute(certex.CKA_MODULUS_BITS, nil),
	// 	certex.NewAttribute(certex.CKA_MODULUS, nil),
	// 	// certex.NewAttribute(certex.CKA_VALUE, nil),
	// }
	o := findObjectsTest(t, fPrivKey)
	for i := range o {
		// t.Log(o[i].Attribute(certex.CKA_MODULUS_BITS))
		// if l == "TIMSAN_RSA_TEST_KEY_LABEL" {
		if err := o[i].DestroyObject(); err != nil {
			t.Log(err)
		}
		// if err := o[i].DestroyObject(); err != nil {
		// }
		// }
		// a, err := o[i].GetAttributeValue(attrs)
		// if err != nil {
		// 	t.Fatal(err)
		// }
		// for n := range a {
		// 	t.Log(a[n].Value)
		// }

	}
}
