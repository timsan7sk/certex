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

CK_RV verify_init(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE pKey) {
	return (*fl->C_VerifyInit)(hSession, pMechanism, pKey);
}
CK_RV verify(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG pSignatureLen) {
	return (*fl->C_Verify)(hSession, pData, ulDataLen, pSignature, pSignatureLen);
}
CK_RV verify_update(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
	return (*fl->C_VerifyUpdate)(hSession, pPart, ulPartLen);
}
CK_RV verify_final(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG pSignatureLen) {
	return (*fl->C_VerifyFinal)(hSession, pSignature, pSignatureLen);
}
*/
import "C"
import "fmt"

// Initializes a verification operation, where the
// signature is an appendix to the data, and plaintext cannot
// be recovered from the signature (e.g. DSA).
func (o *Object) VerifyInit(m *Mechanism) error {
	arena, mech := cMechanism(m)
	defer arena.Free()
	if rv := C.verify_init(o.fl, o.h, mech, o.o); rv != C.CKR_OK {
		return fmt.Errorf("verify_init: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}

// Verifies a signature in a single-part operation,
// where the signature is an appendix to the data, and plaintext
// cannot be recovered from the signature.
func (o *Object) Verify(data []byte, signature []byte) error {
	if rv := C.verify(o.fl, o.h, cData(data), C.CK_ULONG(len(data)), cData(signature), C.CK_ULONG(len(signature))); rv != C.CKR_OK {
		return fmt.Errorf("verify: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}

// Continues a multiple-part verification
// operation, where the signature is an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (o *Object) VerifyUpdate(part []byte) error {
	if rv := C.verify_update(o.fl, o.h, cData(part), C.CK_ULONG(len(part))); rv != C.CKR_OK {
		return fmt.Errorf("verify_update: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}

// Finishes a multiple-part verification
// operation, checking the signature.
func (o *Object) VerifyFinal(signature []byte) error {
	if rv := C.verify_final(o.fl, o.h, cData(signature), C.CK_ULONG(len(signature))); rv != C.CKR_OK {
		return fmt.Errorf("verify_update: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}
