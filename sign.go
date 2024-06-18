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
CK_RV sign(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR *pSignature, CK_ULONG_PTR pulSignatureLen) {
	CK_RV rv = (*fl->C_Sign)(hSession, pData, ulDataLen, NULL, pulSignatureLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pSignature = calloc(*pulSignatureLen, sizeof(CK_BYTE));
	if (*pSignature == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_Sign)(hSession, pData, ulDataLen, *pSignature, pulSignatureLen);
	return rv;
}
CK_RV sign_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pMessage, CK_ULONG ulMessageLen) {
	return (*fl->C_SignUpdate)(hSession, pMessage, ulMessageLen);
}
CK_RV sign_final(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR *pSignature, CK_ULONG_PTR pulSignatureLen) {
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
	"unsafe"
)

// Initializes a signature (private key encryption) operation, where the signature is (will be) an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (o *Object) SignInit(mech *Mechanism) error {
	var arena, cm = cMechanism(mech)
	defer arena.Free()
	if rv := C.sign_init(o.fl, o.h, cm, o.o); rv != C.CKR_OK {
		return fmt.Errorf("sign_init: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}

// Signs (encrypts with private key) data in a single part, where the signature is (will be) an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (o *Object) Sign(data []byte) ([]byte, error) {
	var cSig C.CK_BYTE_PTR
	var cSigLen C.CK_ULONG
	if rv := C.sign(o.fl, o.h, cData(data), C.CK_ULONG(len(data)), &cSig, &cSigLen); rv != C.CKR_OK {
		return nil, fmt.Errorf("sign: 0x%x : %s", rv, returnValues[rv])
	}
	s := C.GoBytes(unsafe.Pointer(cSig), C.int(cSigLen))
	C.free(unsafe.Pointer(cSig))
	return s, nil
}

// Continues a multiple-part signature operation, where the signature is (will be) an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (o *Object) SignUpdate(message []byte) error {

	if rv := C.sign_update(o.fl, o.h, cData(message), C.CK_ULONG(len(message))); rv != C.CKR_OK {
		return fmt.Errorf("sign_update: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}

// Finishes a multiple-part signature operation, returning the signature.
func (o *Object) SignFinal() ([]byte, error) {
	var cSig C.CK_BYTE_PTR
	var cSigLen C.CK_ULONG

	if rv := C.sign_final(o.fl, o.h, &cSig, &cSigLen); rv != C.CKR_OK {
		return nil, fmt.Errorf("sign_final: 0x%x : %s", rv, returnValues[rv])
	}
	s := C.GoBytes(unsafe.Pointer(cSig), C.int(cSigLen))
	C.free(unsafe.Pointer(cSig))
	return s, nil
}
