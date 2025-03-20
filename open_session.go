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

CK_RV open_session(CK_FUNCTION_LIST_PTR fl, CK_SLOT_ID slotID, CK_FLAGS flags, CK_SESSION_HANDLE_PTR phSession) {
	return (*fl->C_OpenSession)(slotID, flags, NULL_PTR, NULL_PTR, phSession);
}
*/
import "C"
import "fmt"

func (m *Cryptoki) openSession(id uint32, opts Options) (C.CK_SESSION_HANDLE, error) {
	var hSession C.CK_SESSION_HANDLE

	if opts.AdminPIN != "" && opts.PIN != "" {
		return hSession, fmt.Errorf("openSession: can't specify pin and admin pin")
	}

	var flags C.CK_FLAGS = C.CKF_SERIAL_SESSION

	if opts.ReadWrite {
		flags = flags | C.CKF_RW_SESSION
	}
	if rv := C.open_session(m.fl, C.CK_SLOT_ID(id), flags, &hSession); rv != C.CKR_OK {
		return hSession, fmt.Errorf("openSession: 0x%08x : %s", rv, returnValues[rv])
	}

	return hSession, nil
}
