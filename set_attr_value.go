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

CK_RV set_attribute_value(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	return (*fl->C_SetAttributeValue)(hSession, hObject, pTemplate, ulCount);
}
*/
import "C"
import "fmt"

func (o Object) setAttributeValue(attrs []C.CK_ATTRIBUTE) error {
	if rv := C.set_attribute_value(o.fl, o.h, o.o, &attrs[0], C.CK_ULONG(len(attrs))); rv != C.CKR_OK {
		return fmt.Errorf("setAttributeValue: 0x%08x : %s", rv, returnValues[rv])

	}
	return nil
}
