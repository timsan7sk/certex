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

CK_RV get_info(CK_FUNCTION_LIST_PTR fl,	CK_INFO_PTR pInfo) {
	return (*fl->C_GetInfo)(pInfo);
}
*/
import "C"
import (
	"fmt"
)

func getInfo(p C.CK_FUNCTION_LIST_PTR) (C.CK_INFO, error) {
	var info C.CK_INFO
	if rv := C.get_info(p, &info); rv != C.CKR_OK {
		return info, fmt.Errorf("getInfo: 0x%x : %s - dlerror: %s", rv, returnValues[rv], C.GoString(C.dlerror()))
	}
	return info, nil
}
