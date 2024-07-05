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

CK_RV destroy_object(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
	return (*fl->C_DestroyObject)(hSession, hObject);
}
*/
import "C"
import "fmt"

// Destroys an object.
func (o *Object) DestroyObject() error {
	if rv := C.destroy_object(o.fl, o.h, o.o); rv != C.CKR_OK {
		return fmt.Errorf("DestroyObject: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}
