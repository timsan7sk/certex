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

CK_RV initialize(CK_FUNCTION_LIST_PTR fl, CK_C_INITIALIZE_ARGS_PTR pInitArgs) {
	return (*fl->C_Initialize)((CK_VOID_PTR)(pInitArgs));
}
*/
import "C"
import (
	"fmt"
)

func initialize(p C.CK_FUNCTION_LIST_PTR) error {
	// var cm C.CK_CREATEMUTEX
	// var dm C.CK_DESTROYMUTEX
	// var lm C.CK_LOCKMUTEX
	// var um C.CK_UNLOCKMUTEX
	// var pr C.CK_VOID_PTR
	args := C.CK_C_INITIALIZE_ARGS{
		// CreateMutex:  cm,
		// DestroyMutex: dm,
		// LockMutex:    lm,
		// UnlockMutex:  um,
		// pReserved:    pr,
		flags: C.CKF_OS_LOCKING_OK,
	}
	rv := C.initialize(p, &args)
	if rv != C.CKR_OK {
		return fmt.Errorf("initialize: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}
