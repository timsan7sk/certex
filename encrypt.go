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

CK_RV encrypt_init(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	return (*fl->C_EncryptInit)(hSession, pMechanism, hKey);
}
CK_RV encrypt(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR *pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
	CK_RV rv = (*fl->C_Encrypt)(hSession, pData, ulDataLen, NULL, pulEncryptedDataLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pEncryptedData = calloc(*pulEncryptedDataLen, sizeof(CK_BYTE));
	if (*pEncryptedData == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_Encrypt)(hSession, pData, ulDataLen, *pEncryptedData, pulEncryptedDataLen);
	return rv;
}
CK_RV encrypt_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR * pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
	CK_RV rv = (*fl->C_EncryptUpdate)(hSession, pPart, ulPartLen, NULL, pulEncryptedPartLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pEncryptedPart = calloc(*pulEncryptedPartLen, sizeof(CK_BYTE));
	if (*pEncryptedPart == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_EncryptUpdate)(hSession, pPart, ulPartLen, *pEncryptedPart, pulEncryptedPartLen);
	return rv;
}
CK_RV encrypt_final(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR * pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
	CK_RV rv = (*fl->C_EncryptFinal)(hSession, NULL, pulLastEncryptedPartLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pLastEncryptedPart = calloc(*pulLastEncryptedPartLen, sizeof(CK_BYTE));
	if (*pLastEncryptedPart == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_EncryptFinal)(hSession, *pLastEncryptedPart, pulLastEncryptedPartLen);
	return rv;
}

*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Initializes an encryption operation.
func (o *Object) EncryptInit(m *Mechanism) error {
	arena, cm := cMechanism(m)
	defer arena.Free()

	if rv := C.encrypt_init(o.fl, o.h, cm, o.o); rv != C.CKR_OK {
		return fmt.Errorf("encrypt_init: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}

// Encrypts single-part data.
func (o *Object) Encrypt(data []byte) ([]byte, error) {
	var (
		enc    C.CK_BYTE_PTR
		enclen C.CK_ULONG
	)
	if rv := C.encrypt(o.fl, o.h, cData(data), C.CK_ULONG(len(data)), &enc, &enclen); rv != C.CKR_OK {
		return nil, fmt.Errorf("encrypt: 0x%08x : %s", rv, returnValues[rv])
	}
	s := C.GoBytes(unsafe.Pointer(&enc), C.int(enclen))
	C.free(unsafe.Pointer(enc))

	return s, nil
}

// Continues a multiple-part encryption operation.
func (o *Object) EncryptUpdate(plain []byte) ([]byte, error) {
	var (
		part    C.CK_BYTE_PTR
		partlen C.CK_ULONG
	)
	if rv := C.encrypt_update(o.fl, o.h, cData(plain), C.CK_ULONG(len(plain)), &part, &partlen); rv != C.CKR_OK {
		return nil, fmt.Errorf("encrypt_final: 0x%08x : %s", rv, returnValues[rv])
	}

	h := C.GoBytes(unsafe.Pointer(part), C.int(partlen))
	C.free(unsafe.Pointer(part))
	return h, nil
}

// Finishes a multiple-part encryption operation.
func (o *Object) EncryptFinal() ([]byte, error) {
	var (
		enc    C.CK_BYTE_PTR
		enclen C.CK_ULONG
	)
	if rv := C.encrypt_final(o.fl, o.h, &enc, &enclen); rv != C.CKR_OK {
		return nil, fmt.Errorf("encrypt_final: 0x%08x : %s", rv, returnValues[rv])
	}
	h := C.GoBytes(unsafe.Pointer(enc), C.int(enclen))
	C.free(unsafe.Pointer(enc))
	return h, nil
}
