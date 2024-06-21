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

CK_RV create_object(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
	return (*fl->C_CreateObject)(hSession, pTemplate, ulCount, phObject);
}
*/
import "C"
import (
	"fmt"
)

func (s *Slot) CreateObject(attrs []*Attribute) (ObjectHandle, error) {
	var hObject C.CK_OBJECT_HANDLE
	arena, cAttrs, ulCount := cAttribute(attrs)
	defer arena.Free()
	if rv := C.create_object(s.fl, s.h, cAttrs, ulCount, &hObject); rv != C.CKR_OK {
		return 0, fmt.Errorf("CreateObject: 0x%x : %s", rv, returnValues[rv])
	}
	return ObjectHandle(hObject), nil
}
