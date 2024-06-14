package certex

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "./headers/cryptoki.h"
#include "./headers/pkcs11def.h"
#include "./headers/pkcs11t.h"
#include "./headers/PKICertexHSM.h"

*/
import "C"
import "fmt"

// The primary object type. Such as a certificate, public key, or
// private key.
type Class int

// Set of classes supported by this package.
const (
	ClassData             Class = 0x00000000
	ClassCertificate      Class = 0x00000001
	ClassPublicKey        Class = 0x00000002
	ClassPrivateKey       Class = 0x00000003
	ClassSecretKey        Class = 0x00000004
	ClassDomainParameters Class = 0x00000006
)

var classString = map[Class]string{
	ClassData:             "CKO_DATA",
	ClassCertificate:      "CKO_CERTIFICATE",
	ClassPublicKey:        "CKO_PUBLIC_KEY",
	ClassPrivateKey:       "CKO_PRIVATE_KEY",
	ClassSecretKey:        "CKO_SECRET_KEY",
	ClassDomainParameters: "CKO_DOMAIN_PARAMETERS",
}

// Returns a human readable version of the object class.
func (c Class) String() string {
	if s, ok := classString[c]; ok {
		return s
	}
	return fmt.Sprintf("Class(0x%08x)", int(c))
}

func (c Class) ckType() (C.CK_OBJECT_CLASS, bool) {
	switch c {
	case ClassData:
		return C.CKO_DATA, true
	case ClassCertificate:
		return C.CKO_CERTIFICATE, true
	case ClassPublicKey:
		return C.CKO_PUBLIC_KEY, true
	case ClassPrivateKey:
		return C.CKO_PRIVATE_KEY, true
	case ClassSecretKey:
		return C.CKO_SECRET_KEY, true
	case ClassDomainParameters:
		return C.CKO_DOMAIN_PARAMETERS, true
	}
	return 0, false
}
