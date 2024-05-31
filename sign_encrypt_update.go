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

CK_RV sign_encrypt_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR *pEncryptedPart, CK_ULONG_PTR ulEncryptedPartLen) {
	CK_RV rv =(*fl->C_SignEncryptUpdate)(hSession, pPart, ulPartLen, NULL, ulEncryptedPartLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pEncryptedPart = calloc(*ulEncryptedPartLen, sizeof(CK_BYTE));
	if (*pEncryptedPart == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_SignEncryptUpdate)(hSession, pPart, ulPartLen, *pEncryptedPart, ulEncryptedPartLen);
	return rv;
}
*/
import "C"

func (o *Object) SignEncryptUpdate() error {
	return nil
}
