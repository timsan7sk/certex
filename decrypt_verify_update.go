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

CK_RV decrypt_verify_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR *pPart, CK_ULONG_PTR pulPartLen) {
	CK_RV rv = (*fl->C_DecryptVerifyUpdate)(hSession, pEncryptedPart, ulEncryptedPartLen, NULL, pulPartLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pPart = calloc(*pulPartLen, sizeof(CK_BYTE));
	if (*pPart == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_DecryptVerifyUpdate)(hSession, pEncryptedPart, ulEncryptedPartLen, *pPart, pulPartLen);
	return rv;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Continues a multiple-part decryption and verify operation.
func (o *Object) DecryptVerifyUpdate(encPart []byte) ([]byte, error) {
	var (
		part    C.CK_BYTE_PTR
		partLen C.CK_ULONG
	)
	if rv := C.decrypt_verify_update(o.fl, o.h, cData(encPart), C.CK_ULONG(len(encPart)), &part, &partLen); rv != C.CKR_OK {
		return nil, fmt.Errorf("decrypt_verify_update: 0x%08x : %s", rv, returnValues[rv])
	}
	d := C.GoBytes(unsafe.Pointer(part), C.int(partLen))
	C.free(unsafe.Pointer(part))
	return d, nil
}
