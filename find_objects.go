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

CK_RV find_objects_init(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	return (*fl->C_FindObjectsInit)(hSession, pTemplate, ulCount);
}

CK_RV find_objects(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
	return (*fl->C_FindObjects)(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

CK_RV find_objects_final(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession) {
	return (*fl->C_FindObjectsFinal)(hSession);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func (s *Slot) FindObjects(opts Filter) (objs []Object, err error) {
	var attrs []C.CK_ATTRIBUTE
	if opts.Label != "" {
		cs, free := ckCString(opts.Label)
		defer free()

		attrs = append(attrs, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(cs),
			C.CK_ULONG(len(opts.Label)),
		})
	}
	if opts.Class != 0 {
		c, ok := Class(opts.Class).ckType()
		if ok {
			objClass := C.CK_OBJECT_CLASS_PTR(C.malloc(C.sizeof_CK_OBJECT_CLASS))
			defer C.free(unsafe.Pointer(objClass))

			*objClass = c
			attrs = append(attrs, C.CK_ATTRIBUTE{
				C.CKA_CLASS,
				C.CK_VOID_PTR(objClass),
				C.CK_ULONG(C.sizeof_CK_OBJECT_CLASS),
			})
		}
	}
	var rv C.CK_RV
	if len(attrs) > 0 {
		rv = C.find_objects_init(s.fl, s.h, &attrs[0], C.CK_ULONG(len(attrs)))

	} else {
		rv = C.find_objects_init(s.fl, s.h, nil, 0)
	}
	if rv != C.CKR_OK {
		err = fmt.Errorf("find_objects_init: 0x%08x : %s", rv, returnValues[rv])
		return nil, err
	}
	defer func() {
		if rv := C.find_objects_final(s.fl, s.h); rv != C.CKR_OK && err == nil {
			err = fmt.Errorf("find_objects_final: 0x%08x : %s", rv, returnValues[rv])
		}
	}()
	var handles []C.CK_OBJECT_HANDLE
	const objectsAtATime = 16
	for {
		cObjHandles := make([]C.CK_OBJECT_HANDLE, objectsAtATime)
		cObjMax := C.CK_ULONG(objectsAtATime)

		var n C.CK_ULONG

		if rv := C.find_objects(s.fl, s.h, &cObjHandles[0], cObjMax, &n); rv != C.CKR_OK {

			err = fmt.Errorf("find_objects: 0x%08x : %s", rv, returnValues[rv])
			return nil, err
		}
		if n == 0 {
			break
		}

		handles = append(handles, cObjHandles[:int(n)]...)
	}

	for _, h := range handles {
		o, err := s.newObject(h)
		if err != nil {
			return nil, err
		}
		objs = append(objs, o)
	}
	return objs, nil

}
