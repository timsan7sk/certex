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

CK_RV get_function_status(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession) {
	return (*fl->C_GetFunctionStatus)(hSession);
}
*/
import "C"
