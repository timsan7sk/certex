package tests

import (
	"certex"
	"testing"
)

var fPrivKey = certex.Filter{
	Class: certex.ClassPrivateKey,
	Label: "",
}

//	var fPubKey = certex.Filter{
//		Class: certex.ClassPublicKey,
//		Label: "",
//	}
//
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
	findObjectsTest(t, fCert)
}
