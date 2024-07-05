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

CK_RV copy_object(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
	return (*fl->C_CopyObject)(hSession, hObject, pTemplate, ulCount, phNewObject);
}
*/
import "C"
import "fmt"

// Copies an object, creating a new object for the copy and return the handle to the new object.
func (o *Object) CopyObject(attrs []*Attribute) (Object, error) {
	var hNewObject C.CK_OBJECT_HANDLE
	arena, cAttrs, ulCount := cAttribute(attrs)
	defer arena.Free()
	if rv := C.copy_object(o.fl, o.h, o.o, cAttrs, ulCount, &hNewObject); rv != C.CKR_OK {
		return Object{}, fmt.Errorf("copy_object: 0x%08x : %s", rv, returnValues[rv])
	}
	obj, err := o.newObject(hNewObject)
	if err != nil {
		return Object{}, fmt.Errorf("newObject: %s", err)
	}
	return obj, nil
}
