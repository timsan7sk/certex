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

// Label возвращает строковую метку CKA_LABEL объекта в токене PKCS#11.
func (o Object) Label() (string, error) {
	attrs := []C.CK_ATTRIBUTE{{C.CKA_LABEL, nil, 0}}
	if err := o.getAttributeValue(attrs); err != nil {
		return "", err
	}
	if attrs[0].pValue == nil || int64(attrs[0].ulValueLen) <= 0 {
		return "", nil
	}
	defer C.free(unsafe.Pointer(attrs[0].pValue))

	return ckGoString((*C.CK_UTF8CHAR)(attrs[0].pValue), attrs[0].ulValueLen), nil
}
