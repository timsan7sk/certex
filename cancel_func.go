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

CK_RV cancel_function(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession) {
	return (*fl->C_CancelFunction)(hSession);
}
*/
import "C"
