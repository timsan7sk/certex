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

CK_RV unwrap_key(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
	CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
	return (*fl->C_UnwrapKey)(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func (o *Object) UnwrapKey(m *Mechanism, unwrappingKey ObjectHandle, wrappedKey []byte, a []*Attribute) (ObjectHandle, error) {
	var key C.CK_OBJECT_HANDLE
	attrarena, caa, caalen := cAttributeArray(a)
	defer attrarena.Free()
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()

	if rv := C.unwrap_key(o.fl, o.h, mech, C.CK_OBJECT_HANDLE(unwrappingKey), C.CK_BYTE_PTR(unsafe.Pointer(&wrappedKey[0])), C.CK_ULONG(len(wrappedKey)), caa, caalen, &key); rv != C.CKR_OK {
		return 0, fmt.Errorf("unwrap_key: 0x%x : %s", rv, returnValues[rv])
	}
	return ObjectHandle(key), nil
}
