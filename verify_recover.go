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

CK_RV verify_recover_init(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE pKey) {
	return (*fl->C_VerifyRecoverInit)(hSession, pMechanism, pKey);
}
CK_RV verify_recover(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG pSignatureLen, CK_BYTE_PTR *pData, CK_ULONG_PTR pDataLen) {
	CK_RV rv = (*fl->C_VerifyRecover)(hSession, pSignature, pSignatureLen, NULL, pDataLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pData = calloc(*pDataLen, sizeof(CK_BYTE));
	if (*pData == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_VerifyRecover)(hSession, pSignature, pSignatureLen, *pData, pDataLen);
	return rv;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Initializes a signature verification
// operation, where the data is recovered from the signature.
func (o *Object) VerifyRecoverInit(m *Mechanism) error {
	arena, mech := cMechanism(m)
	defer arena.Free()
	if rv := C.verify_recover_init(o.fl, o.h, mech, o.o); rv != C.CKR_OK {
		return fmt.Errorf("verify_recover_init: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}

// Verifies a signature in a single-part operation,
// where the data is recovered from the signature.
func (o *Object) VerifyRecover(signature []byte) ([]byte, error) {
	var (
		data    C.CK_BYTE_PTR
		datalen C.CK_ULONG
	)
	if rv := C.verify_recover(o.fl, o.h, cData(signature), C.CK_ULONG(len(signature)), &data, &datalen); rv != C.CKR_OK {
		return nil, fmt.Errorf("verify_recover: 0x%08x : %s", rv, returnValues[rv])
	}
	r := C.GoBytes(unsafe.Pointer(data), C.int(datalen))
	C.free(unsafe.Pointer(data))
	return r, nil
}
