package certex

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>

#include "./headers/cryptoki.h"
#include "./headers/pkcs11def.h"
#include "./headers/pkcs11t.h"
#include "./headers/PKICertexHSM.h"

CK_RV get_object_size(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
	return (*fl->C_GetObjectSize)(hSession, hObject, pulSize);
}
*/
import "C"
import "fmt"

// Gets the size of an object in bytes.
func (o *Object) GetObjectSize() (uint, error) {
	var size C.CK_ULONG
	if rv := C.get_object_size(o.fl, o.h, o.o, &size); rv != C.CKR_OK {
		return 0, fmt.Errorf("GetObjectSize: 0x%x : %s", rv, returnValues[rv])
	}
	return uint(size), nil
}
