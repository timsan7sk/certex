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

CK_RV login(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
	return (*fl->C_Login)(hSession, userType, pPin, ulPinLen);
}
*/
import "C"
import (
	"fmt"
)

func (s *Slot) login(pin string, userType uint) error {
	// TODO: check for CKR_USER_ALREADY_LOGGED_IN and auto logout.
	// TODO: maybe run commands, detect CKR_USER_NOT_LOGGED_IN, then automatically login?
	if pin == "" {
		return fmt.Errorf("login: invalid pin")
	}
	cPIN := ckString(pin)
	cPINLen := C.CK_ULONG(len(cPIN))
	if rv := C.login(s.fl, s.h, C.CK_USER_TYPE(userType), &cPIN[0], cPINLen); rv != C.CKR_OK {
		return fmt.Errorf("login: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}
