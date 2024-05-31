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

CK_RV digest_encrypt_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR *pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
	CK_RV rv = (*fl->C_DigestEncryptUpdate)(hSession, pPart, ulPartLen, NULL, pulEncryptedPartLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pEncryptedPart = calloc(*pulEncryptedPartLen, sizeof(CK_BYTE));
	if (*pEncryptedPart == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_DigestEncryptUpdate)(hSession, pPart, ulPartLen, *pEncryptedPart, pulEncryptedPartLen);
	return rv;
}
*/
import "C"

func (o *Object) DigestEncryptUpdate() error {
	return nil
}
