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

CK_RV initialize(CK_FUNCTION_LIST_PTR fl) {
	CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)calloc(1, sizeof(CK_C_INITIALIZE_ARGS));
	if (args == NULL_PTR) {
		return CKR_HOST_MEMORY;
	}
	args->flags = CKF_OS_LOCKING_OK;
	CK_RV rv = (*fl->C_Initialize)((CK_VOID_PTR)args);
	free(args);
	return rv;
}
*/
import "C"
import (
	"fmt"
)

func initialize(p C.CK_FUNCTION_LIST_PTR) error {
	rv := C.initialize(p)
	if rv != C.CKR_OK && rv != C.CKR_CRYPTOKI_ALREADY_INITIALIZED {
		return fmt.Errorf("initialize: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}
