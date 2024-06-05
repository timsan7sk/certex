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

CK_RV finalize(CK_FUNCTION_LIST_PTR fl) {
	return (*fl->C_Finalize)(NULL_PTR);
}
CK_RV close_session(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession) {
	return (*fl->C_CloseSession)(hSession);
}
CK_RV close_all_sessions(CK_FUNCTION_LIST_PTR fl, CK_ULONG slotID) {
	return (*fl->C_CloseAllSessions)(slotID);
}
*/
import "C"
import "fmt"

func (m *Cryptoki) Close() error {
	rv := C.finalize(m.fl)
	if rv != C.CKR_OK {
		// fmt.Printf("finalize: 0x%x\n", rv)
		return fmt.Errorf("finalize: 0x%x : %s", rv, returnValues[rv])
	}
	if C.dlclose(m.mod) != 0 {
		return fmt.Errorf("dlclose: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}

func (s *Slot) Close() error {
	if rv := C.close_session(s.fl, s.h); rv != C.CKR_OK {
		return fmt.Errorf("CloseSession: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}
func (s *Slot) CloseAll(slotID uint32) error {
	if rv := C.close_all_sessions(s.fl, C.CK_ULONG(slotID)); rv != C.CKR_OK {
		return fmt.Errorf("CloseAllSession: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}
