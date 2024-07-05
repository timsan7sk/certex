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

CK_RV set_operation_state(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
	return (*fl->C_SetOperationState)(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
}

*/
import "C"
import (
	"fmt"
	"unsafe"
)

func (s *Slot) SetOperationState(operationState []byte, hEncryptionKey, hAuthenticationKey C.CK_OBJECT_HANDLE) error {
	if rv := C.set_operation_state(s.fl, s.h, C.CK_BYTE_PTR(unsafe.Pointer(&operationState[0])), C.CK_ULONG(len(operationState)), hEncryptionKey, hAuthenticationKey); rv != C.CKR_OK {
		return fmt.Errorf("SetOperationState: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}
