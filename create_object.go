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

var obj Object

func (s *Slot) CreateObject(attrs []C.CK_ATTRIBUTE, opts slotOptions) (*Object, error) {
	if opts.Label != "" {
		cs, free := ckCString(opts.Label)
		defer free()

		attrs = append(attrs, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(cs),
			C.CK_ULONG(len(opts.Label)),
		})
	}
	var h C.CK_OBJECT_HANDLE
	if rv := C.create_object(s.fl, s.h, &attrs[0], C.CK_ULONG(len(attrs)), &h); rv != C.CKR_OK {
		return nil, fmt.Errorf("CreateObject: 0x%x : %s", rv, returnValues[rv])
	}
	obj, err := s.newObject(h)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}
