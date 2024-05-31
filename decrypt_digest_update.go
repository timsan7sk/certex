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

CK_RV decrypt_digest_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR *pPart, CK_ULONG_PTR pulPartLen) {
	CK_RV rv = (*fl->C_DecryptDigestUpdate)(hSession, pEncryptedPart, ulEncryptedPartLen, NULL, pulPartLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pPart = calloc(*pulPartLen, sizeof(CK_BYTE));
	if (*pPart == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_DecryptDigestUpdate)(hSession, pEncryptedPart, ulEncryptedPartLen, *pPart, pulPartLen);
	return rv;
}
*/
import "C"

func (o *Object) DecryptDigestUpdate() error {
	return nil
}
