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

CK_RV initialize(CK_FUNCTION_LIST_PTR fl, CK_C_INITIALIZE_ARGS_PTR pInitArgs) {
	return (*fl->C_Initialize)((CK_VOID_PTR)(pInitArgs));
}
*/
import "C"
import "fmt"

func initialize(p C.CK_FUNCTION_LIST_PTR) error {
	args := C.CK_C_INITIALIZE_ARGS{
		flags: C.CKF_OS_LOCKING_OK,
	}
	rv := C.initialize(p, &args)
	if rv != C.CKR_OK {
		return fmt.Errorf("initialize: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}
