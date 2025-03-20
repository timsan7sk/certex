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

CK_RV logout(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession) {
	return (*fl->C_Logout)(hSession);
}
*/
import "C"
import "fmt"

func (s *Slot) logout() error {
	if rv := C.logout(s.fl, s.h); rv != C.CKR_OK {
		return fmt.Errorf("logout: 0x%08x : %s", rv, returnValues[rv])
	}
	return nil
}
