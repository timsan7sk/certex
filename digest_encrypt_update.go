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

CK_RV digest_encrypt_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
	CK_RV rv = (*fl->C_DigestEncryptUpdate)(hSession, pPart, ulPartLen, NULL, pulEncryptedPartLen);
	if (rv != CKR_OK) {
		return rv;
	}
	pEncryptedPart = calloc(*pulEncryptedPartLen, sizeof(CK_BYTE));
	if (pEncryptedPart == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_DigestEncryptUpdate)(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	return rv;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Continues a multiple-part digesting and encryption operation.
func (o *Object) DigestEncryptUpdate(part []byte) ([]byte, error) {
	var (
		encPart    C.CK_BYTE_PTR
		encPartLen C.CK_ULONG
	)
	if rv := C.digest_encrypt_update(o.fl, o.h, cData(part), C.CK_ULONG(len(part)), encPart, &encPartLen); rv != C.CKR_OK {
		return nil, fmt.Errorf("digest_encrypt_update: 0x%08x : %s", rv, returnValues[rv])
	}
	d := C.GoBytes(unsafe.Pointer(encPart), C.int(encPartLen))
	C.free(unsafe.Pointer(encPart))
	return d, nil
}
