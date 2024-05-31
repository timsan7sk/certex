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

CK_RV init_pin(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
	return (*fl->C_InitPIN)(hSession, pPin, ulPinLen);
}
*/
import "C"
import "fmt"

func (s *Slot) initPIN(pin string) error {
	if pin == "" {
		return fmt.Errorf("initPIN: invalid pin")
	}
	cPIN := ckString(pin)
	cPINLen := C.CK_ULONG(len(cPIN))
	if rv := C.init_pin(s.fl, s.h, &cPIN[0], cPINLen); rv != C.CKR_OK {
		return fmt.Errorf("initPIN: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}
