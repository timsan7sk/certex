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

CK_RV decrypt_init(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	return (*fl->C_DecryptInit)(hSession, pMechanism, hKey);
}
CK_RV decrypt(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR * pData, CK_ULONG_PTR pulDataLen) {
	CK_RV rv = (*fl->C_Decrypt)(hSession, pEncryptedData, ulEncryptedDataLen, NULL, pulDataLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pData = calloc(*pulDataLen, sizeof(CK_BYTE));
	if (*pData == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_Decrypt)(hSession, pEncryptedData, ulEncryptedDataLen, *pData, pulDataLen);
	return rv;
}
CK_RV decrypt_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR *pPart, CK_ULONG_PTR pulPartLen) {
	CK_RV rv = (*fl->C_DecryptUpdate)(hSession, pEncryptedPart, ulEncryptedPartLen, NULL, pulPartLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pPart = calloc(*pulPartLen, sizeof(CK_BYTE));
	if (*pPart == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_DecryptUpdate)(hSession, pEncryptedPart, ulEncryptedPartLen, *pPart, pulPartLen);
	return rv;
}
CK_RV decrypt_final(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR *pLastPart, CK_ULONG_PTR pulLastPartLen) {
	CK_RV rv = (*fl->C_DecryptFinal)(hSession, NULL, pulLastPartLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pLastPart = calloc(*pulLastPartLen, sizeof(CK_BYTE));
	if (*pLastPart == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_DecryptFinal)(hSession, *pLastPart, pulLastPartLen);
	return rv;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Initializes a decryption operation.
func (o *Object) DecryptInit(m *Mechanism) error {
	arena, cm := cMechanism(m)
	defer arena.Free()

	if rv := C.decrypt_init(o.fl, o.h, cm, o.o); rv != C.CKR_OK {
		return fmt.Errorf("decrypt_init: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}

// Decrypts encrypted data in a single part.
func (o *Object) Decrypt(data []byte) ([]byte, error) {
	var (
		plain    C.CK_BYTE_PTR
		plainlen C.CK_ULONG
	)

	if rv := C.decrypt(o.fl, o.h, cData(data), C.CK_ULONG(len(data)), &plain, &plainlen); rv != C.CKR_OK {
		return nil, fmt.Errorf("encrypt: 0x%08x : %s", rv, returnValues[rv])
	}
	s := C.GoBytes(unsafe.Pointer(&plain), C.int(plainlen))
	C.free(unsafe.Pointer(plain))

	return s, nil
}

// Continues a multiple-part decryption operation.
func (o *Object) DecryptUpdate(cipher []byte) ([]byte, error) {
	var (
		part    C.CK_BYTE_PTR
		partlen C.CK_ULONG
	)
	if rv := C.decrypt_update(o.fl, o.h, cData(cipher), C.CK_ULONG(len(cipher)), &part, &partlen); rv != C.CKR_OK {
		return nil, fmt.Errorf("encrypt_final: 0x%08x : %s", rv, returnValues[rv])
	}

	h := C.GoBytes(unsafe.Pointer(part), C.int(partlen))
	C.free(unsafe.Pointer(part))
	return h, nil
}

// Finishes a multiple-part decryption operation.
func (o *Object) DecryptFinal() ([]byte, error) {
	var (
		plain    C.CK_BYTE_PTR
		plainlen C.CK_ULONG
	)
	if rv := C.decrypt_final(o.fl, o.h, &plain, &plainlen); rv != C.CKR_OK {
		return nil, fmt.Errorf("encrypt_final: 0x%08x : %s", rv, returnValues[rv])
	}
	h := C.GoBytes(unsafe.Pointer(plain), C.int(plainlen))
	C.free(unsafe.Pointer(plain))
	return h, nil
}
