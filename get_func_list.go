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

CK_RV get_function_list(CK_C_GetFunctionList fn, CK_FUNCTION_LIST_PTR_PTR ppFunctionList) { return (*fn)(ppFunctionList); }
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func getFunctionList(pLib unsafe.Pointer, p C.CK_FUNCTION_LIST_PTR) (C.CK_FUNCTION_LIST_PTR, error) {

	cSym := C.CString("C_GetFunctionList")
	defer C.free(unsafe.Pointer(cSym))

	fn := (C.CK_C_GetFunctionList)(C.dlsym(pLib, cSym))
	if fn == nil {
		C.dlclose(pLib)
		return nil, fmt.Errorf("lookup function list symbol: %s", C.GoString(C.dlerror()))
	}
	rv := C.get_function_list(fn, &p)
	// fmt.Printf("CK_FUNCTION_LIST: %+v\n", p)
	if rv != C.CKR_OK {
		C.dlclose(pLib)
		return nil, fmt.Errorf("get_function_list: %s, rv: 0x%08x", returnValues[rv], rv)
	}

	return p, nil
}
