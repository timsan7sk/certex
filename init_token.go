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

CK_RV init_token(CK_FUNCTION_LIST_PTR fl, CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
	if (ulPinLen == 0) {
		// TODO(timsan): This isn't tested since softhsm requires a PIN.
		pPin = NULL_PTR;
	}
	return (*fl->C_InitToken)(slotID, pPin, ulPinLen, pLabel);
}

*/
import "C"
import (
	"fmt"
	"reflect"
)

// Initializes a token.
func (m *Cryptoki) InitToken(id uint32, opts SlotOptions) error {
	v := reflect.ValueOf(opts)
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).String() == "" {
			return fmt.Errorf("InitToken: %s not provided", t.Field(i).Name)
		}
	}

	var cLabel [32]C.CK_UTF8CHAR
	if !ckStringPadded(cLabel[:], opts.Label) {
		return fmt.Errorf("InitToken: label too long")
	}
	cPIN := ckString(opts.AdminPIN)
	cPINLen := C.CK_ULONG(len(cPIN))

	if rv := C.init_token(m.fl, C.CK_SLOT_ID(id), &cPIN[0], cPINLen, &cLabel[0]); rv != C.CKR_OK {
		return fmt.Errorf("init_token: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}
