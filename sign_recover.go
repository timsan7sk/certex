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

CK_RV sign_recover_init(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	return (*fl->C_SignRecoverInit)(hSession, pMechanism, hKey);
}
CK_RV sign_recover(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG pDataLen, CK_BYTE_PTR *pSignature, CK_ULONG_PTR pulSignatureLen) {
	CK_RV rv = (*fl->C_SignRecover)(hSession, pData, pDataLen, NULL, pulSignatureLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pSignature = calloc(*pulSignatureLen, sizeof(CK_BYTE));
	if (*pSignature == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_SignRecover)(hSession, pData, pDataLen, *pSignature, pulSignatureLen);
	return rv;
}
*/
import "C"

func (o *Object) SignRecover() error {
	return nil
}
