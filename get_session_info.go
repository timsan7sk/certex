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

CK_RV get_session_info(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
	return (*fl->C_GetSessionInfo)(hSession, pInfo);
}
*/
import "C"
import "fmt"

func (s *Slot) GetSessionInfo() (SessionInfo, error) {
	var info C.CK_SESSION_INFO
	if rv := C.get_session_info(s.fl, s.h, &info); rv != C.CKR_OK {
		return SessionInfo{}, fmt.Errorf("get_session_info: 0x%x : %s", rv, returnValues[rv])
	}
	si := SessionInfo{SlotID: uint(info.slotID),
		State:       uint(info.state),
		Flags:       uint(info.flags),
		DeviceError: uint(info.ulDeviceError),
	}
	return si, nil
}
