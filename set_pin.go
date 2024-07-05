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

CK_RV set_pin(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, char *OldPin, CK_ULONG ulOldLen, char *NewPin, CK_ULONG ulNewLen) {
	return (*fl->C_SetPIN)(hSession, (CK_UTF8CHAR_PTR) OldPin, ulOldLen, (CK_UTF8CHAR_PTR) NewPin, ulNewLen);
}
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

func (s *Slot) SetPIN(oldPIN, newPIN string) error {
	if oldPIN == "" || newPIN == "" {
		return errors.New("SetPIN: invalid pin")
	}
	old := C.CString(oldPIN)
	defer C.free(unsafe.Pointer(old))
	new := C.CString(newPIN)
	defer C.free(unsafe.Pointer(new))
	if rv := C.set_pin(s.fl, s.h, old, C.CK_ULONG(len(oldPIN)), new, C.CK_ULONG(len(newPIN))); rv != C.CKR_OK {
		return fmt.Errorf("SetPIN: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}
