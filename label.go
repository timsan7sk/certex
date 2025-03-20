package certex

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>

#include "cryptoki.h"
#include "pkcs11def.h"
#include "pkcs11t.h"
#include "PKICertexHSM.h"
*/
import "C"
import "unsafe"

// Returns a string value attached to an object, which can be used to
// identify or group sets of keys and certificates.
func (o Object) Label() (string, error) {
	attrs := []C.CK_ATTRIBUTE{{C.CKA_LABEL, nil, 0}}
	if err := o.getAttributeValue(attrs); err != nil {
		return "", err
	}
	n := attrs[0].ulValueLen

	cLabel := (*C.CK_UTF8CHAR)(C.malloc(C.ulong(n)))
	defer C.free(unsafe.Pointer(cLabel))
	attrs[0].pValue = C.CK_VOID_PTR(cLabel)

	if err := o.getAttributeValue(attrs); err != nil {
		return "", err
	}
	return ckGoString(cLabel, n), nil
}
