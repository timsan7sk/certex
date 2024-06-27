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

CK_RV get_attribute_value(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	return (*fl->C_GetAttributeValue)(hSession, hObject, pTemplate, ulCount);
}
static inline CK_VOID_PTR getAttrPval(CK_ATTRIBUTE_PTR a)
{
	return a->pValue;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func (o Object) getAttributeValue(attrs []C.CK_ATTRIBUTE) error {
	if rv := C.get_attribute_value(o.fl, o.h, o.o, &attrs[0], C.CK_ULONG(len(attrs))); rv != C.CKR_OK {
		return fmt.Errorf("getAttributeValue: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}
func (o Object) GetAttributeValue(attrs []*Attribute) ([]*Attribute, error) {
	cAttrs := make([]C.CK_ATTRIBUTE, len(attrs))
	for i := 0; i < len(attrs); i++ {
		cAttrs[i]._type = C.CK_ATTRIBUTE_TYPE(attrs[i].Type)
	}
	if rv := C.get_attribute_value(o.fl, o.h, o.o, &cAttrs[0], C.CK_ULONG(len(attrs))); rv != C.CKR_OK {
		return nil, fmt.Errorf("get_attribute_value: 0x%x : %s", rv, returnValues[rv])
	}
	pAttrs := make([]*Attribute, len(attrs))
	for i, c := range cAttrs {
		x := new(Attribute)
		x.Type = uint(c._type)
		if int(c.ulValueLen) != -1 {
			buf := unsafe.Pointer(C.getAttrPval(&c))
			x.Value = C.GoBytes(buf, C.int(c.ulValueLen))
			C.free(buf)
		}
		pAttrs[i] = x
	}

	return pAttrs, nil
}
func (s *p) newObject(oh C.CK_OBJECT_HANDLE) (Object, error) {
	objClass := C.CK_OBJECT_CLASS_PTR(C.malloc(C.sizeof_CK_OBJECT_CLASS))
	defer C.free(unsafe.Pointer(objClass))

	a := []C.CK_ATTRIBUTE{
		{C.CKA_CLASS, C.CK_VOID_PTR(objClass), C.CK_ULONG(C.sizeof_CK_OBJECT_CLASS)},
	}

	if rv := C.get_attribute_value(s.fl, s.h, oh, &a[0], C.CK_ULONG(len(a))); rv != C.CKR_OK {
		return Object{}, fmt.Errorf("newObject: 0x%x : %s", rv, returnValues[rv])
	}
	return Object{p{fl: s.fl, h: s.h}, oh, *objClass}, nil
}
