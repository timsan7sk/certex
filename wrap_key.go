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
