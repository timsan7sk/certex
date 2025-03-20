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

CK_RV digest_init(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
	return (*fl->C_DigestInit)(hSession, pMechanism);
}
CK_RV digest(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR * pDigest, CK_ULONG_PTR pulDigestLen) {
	CK_RV rv = (*fl->C_Digest)(hSession, pData, ulDataLen, NULL, pulDigestLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pDigest = calloc(*pulDigestLen, sizeof(CK_BYTE));
	if (*pDigest == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_Digest)(hSession, pData, ulDataLen, *pDigest, pulDigestLen);
	return rv;
}
CK_RV digest_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
	return (*fl->C_DigestUpdate)(hSession, pPart, ulPartLen);
}
CK_RV digest_key(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
	return (*fl->C_DigestKey)(hSession, hKey);
}
CK_RV digest_final(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR *pDigest, CK_ULONG_PTR pulDigestLen) {
	CK_RV rv = (*fl->C_DigestFinal)(hSession, NULL, pulDigestLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pDigest = calloc(*pulDigestLen, sizeof(CK_BYTE));
	if (*pDigest == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_DigestFinal)(hSession, *pDigest, pulDigestLen);
	return rv;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Initializes a message-digesting operation.
func (o *Object) DigestInit(m *Mechanism) error {
	arena, mech := cMechanism(m)
	defer arena.Free()
	if rv := C.digest_init(o.fl, o.h, mech); rv != C.CKR_OK {
		return fmt.Errorf("digest_init: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}

// Digests message in a single part.
func (o *Object) Digest(message []byte) ([]byte, error) {
	var (
		hash    C.CK_BYTE_PTR
		hashlen C.CK_ULONG
	)
	if rv := C.digest(o.fl, o.h, cData(message), C.CK_ULONG(len(message)), &hash, &hashlen); rv != C.CKR_OK {
		return nil, fmt.Errorf("digest: 0x%08x : %s", rv, returnValues[rv])

	}
	h := C.GoBytes(unsafe.Pointer(hash), C.int(hashlen))
	C.free(unsafe.Pointer(hash))
	return h, nil
}

// Continues a multiple-part message-digesting operation.
func (o *Object) DigestUpdate(message []byte) error {
	if rv := C.digest_update(o.fl, o.h, cData(message), C.CK_ULONG(len(message))); rv != C.CKR_OK {
		return fmt.Errorf("digest_update: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}

// Continues a multi-part message-digesting
// operation, by digesting the value of a secret key as part of
// the data already digested.
func (o *Object) DigestKey() error {
	if rv := C.digest_key(o.fl, o.h, o.o); rv != C.CKR_OK {
		return fmt.Errorf("digest_key: 0x%08x : %s", rv, returnValues[rv])

	}
	return nil
}

// Finishes a multiple-part message-digesting operation.
func (o *Object) DigestFinal() ([]byte, error) {
	var (
		hash    C.CK_BYTE_PTR
		hashlen C.CK_ULONG
	)
	if rv := C.digest_final(o.fl, o.h, &hash, &hashlen); rv != C.CKR_OK {
		return nil, fmt.Errorf("digest_final: 0x%08x : %s", rv, returnValues[rv])
	}

	h := C.GoBytes(unsafe.Pointer(hash), C.int(hashlen))
	C.free(unsafe.Pointer(hash))
	return h, nil
}
