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

CK_RV wrap_key(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR *pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
	CK_RV rv = (*fl->C_WrapKey)(hSession, pMechanism, hWrappingKey, hKey, NULL, pulWrappedKeyLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pWrappedKey = calloc(*pulWrappedKeyLen, sizeof(CK_BYTE));
	if (*pWrappedKey == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_WrapKey)(hSession, pMechanism, hWrappingKey, hKey, *pWrappedKey, pulWrappedKeyLen);
	return rv;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Wraps (i.e., encrypts) a private or secret key
// Param key is the Object of the key to be wrapped
func (o *Object) WrapKey(m *Mechanism, key Object) ([]byte, error) {
	var (
		wrappedKey    C.CK_BYTE_PTR
		wrappedKeyLen C.CK_ULONG
	)
	arena, mech := cMechanism(m)
	defer arena.Free()
	if rv := C.wrap_key(o.fl, o.h, mech, o.o, key.o, &wrappedKey, &wrappedKeyLen); rv != C.CKR_OK {
		return nil, fmt.Errorf("wrap_key: 0x%08x : %s", rv, returnValues[rv])
	}
	k := C.GoBytes(unsafe.Pointer(wrappedKey), C.int(wrappedKeyLen))
	C.free(unsafe.Pointer(wrappedKey))
	return k, nil
}
