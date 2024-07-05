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

CK_RV sign_encrypt_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR ulEncryptedPartLen) {
	CK_RV rv =(*fl->C_SignEncryptUpdate)(hSession, pPart, ulPartLen, NULL, ulEncryptedPartLen);
	if (rv != CKR_OK) {
		return rv;
	}
	pEncryptedPart = calloc(*ulEncryptedPartLen, sizeof(CK_BYTE));
	if (pEncryptedPart == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_SignEncryptUpdate)(hSession, pPart, ulPartLen, pEncryptedPart, ulEncryptedPartLen);
	return rv;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Continues a multiple-part signing and encryption operation.
func (o *Object) SignEncryptUpdate(part []byte) ([]byte, error) {
	var (
		encPart    C.CK_BYTE_PTR
		encPartLen C.CK_ULONG
	)
	if rv := C.sign_encrypt_update(o.fl, o.h, cData(part), C.CK_ULONG(len(part)), encPart, &encPartLen); rv != C.CKR_OK {
		return nil, fmt.Errorf("sign_encrypt_update: 0x%08x : %s", rv, returnValues[rv])
	}
	d := C.GoBytes(unsafe.Pointer(encPart), C.int(encPartLen))
	C.free(unsafe.Pointer(encPart))
	return d, nil
}
