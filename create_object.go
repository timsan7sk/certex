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

CK_RV create_object(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
	return (*fl->C_CreateObject)(hSession, pTemplate, ulCount, phObject);
}
*/
import "C"
import (
	"fmt"
)

func (s *Slot) CreateObject(attrs []*Attribute) (Object, error) {
	var hObject C.CK_OBJECT_HANDLE
	arena, cAttrs, ulCount := cAttribute(attrs)
	defer arena.Free()
	if rv := C.create_object(s.fl, s.h, cAttrs, ulCount, &hObject); rv != C.CKR_OK {
		return Object{}, fmt.Errorf("CreateObject: 0x%08x : %s", rv, returnValues[rv])
	}
	o, err := s.newObject(hObject)
	if err != nil {
		return Object{}, fmt.Errorf("newObject: %+v", err)
	}
	return o, nil
}
