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

CK_RV close_session(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession) {
	return (*fl->C_CloseSession)(hSession);
}
CK_RV close_all_sessions(CK_FUNCTION_LIST_PTR fl, CK_ULONG slotID) {
	return (*fl->C_CloseAllSessions)(slotID);
}
*/
import "C"
import "fmt"

func (s *Slot) CloseSession() error {
	if rv := C.close_session(s.fl, s.h); rv != C.CKR_OK {
		return fmt.Errorf("CloseSession: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}
func (s *Slot) CloseAllSessions(slotID uint32) error {
	if rv := C.close_all_sessions(s.fl, C.CK_ULONG(slotID)); rv != C.CKR_OK {
		return fmt.Errorf("CloseAllSession: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}
