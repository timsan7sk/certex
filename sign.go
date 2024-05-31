package certex

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "./headers/cryptoki.h"
#include "./headers/pkcs11def.h"
#include "./headers/pkcs11t.h"
#include "./headers/PKICertexHSM.h"

CK_RV sign_init(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	return (*fl->C_SignInit)(hSession, pMechanism, hKey);
}
CK_RV sign(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
	return (*fl->C_Sign)(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}
CK_RV sign_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pMessage, CK_ULONG ulMessageLen) {
	return (*fl->C_SignUpdate)(hSession, pMessage, ulMessageLen);
}
CK_RV sign_final(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR * pSignature, CK_ULONG_PTR pulSignatureLen) {
	CK_RV rv = (*fl->C_SignFinal)(hSession, NULL, pulSignatureLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pSignature = calloc(*pulSignatureLen, sizeof(CK_BYTE));
	if (*pSignature == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_SignFinal)(hSession, *pSignature, pulSignatureLen);
	return rv;
}
*/
import "C"
import (
	"fmt"
)

func (o *Object) Sign(data []byte, mech *Mechanism) ([]byte, error) {

	cSig := make([]C.CK_BYTE, 128)
	cSigLen := C.CK_ULONG(128)

	var arena, cm = cMechanism(mech)
	defer arena.Free()

	if rv := C.sign_init(o.fl, o.h, cm, o.o); rv != C.CKR_OK {
		return nil, fmt.Errorf("sign_init: 0x%x : %s", rv, returnValues[rv])
	}
	if rv := C.sign(o.fl, o.h, cData(data), C.CK_ULONG(len(data)), &cSig[0], &cSigLen); rv != C.CKR_OK {
		return nil, fmt.Errorf("sign: 0x%x : %s", rv, returnValues[rv])
	}

	return []byte(string(cSig[:])), nil
}
