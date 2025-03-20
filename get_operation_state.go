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

CK_RV get_operation_state(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR * pOperationState, CK_ULONG_PTR pulOperationStateLen) {
	CK_RV rv = (*fl->C_GetOperationState)(hSession, NULL, pulOperationStateLen);
	if (rv != CKR_OK) {
		return rv;
	}
	*pOperationState = calloc(*pulOperationStateLen, sizeof(CK_BYTE));
	if (*pOperationState == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = (*fl->C_GetOperationState)(hSession, *pOperationState, pulOperationStateLen);
	return rv;
}

*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Obtains the state of the cryptographic operation in a session.
func (s *Slot) GetOperationState() ([]byte, error) {
	var (
		pOperationState     C.CK_BYTE_PTR
		ulOperationStateLen C.CK_ULONG
	)
	if rv := C.get_operation_state(s.fl, s.h, &pOperationState, &ulOperationStateLen); rv != C.CKR_OK {
		return nil, fmt.Errorf("GetOperationState: 0x%08x : %s", rv, returnValues[rv])

	}
	defer C.free(unsafe.Pointer(pOperationState))
	b := C.GoBytes(unsafe.Pointer(pOperationState), C.int(ulOperationStateLen))
	return b, nil
}
