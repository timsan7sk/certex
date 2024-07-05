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

CK_RV get_mechanism_info(CK_FUNCTION_LIST_PTR fl, CK_ULONG slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
	return (*fl->C_GetMechanismInfo)((CK_SLOT_ID)slotID, type, pInfo);
}

*/
import "C"
import "fmt"

func (m *Cryptoki) GetMechanismInfo(slotID uint32, mech *Mechanism) (MechanismInfo, error) {
	arena, cm := cMechanism(mech)
	defer arena.Free()
	var pInfo C.CK_MECHANISM_INFO
	if rv := C.get_mechanism_info(m.fl, C.CK_ULONG(slotID), C.CK_MECHANISM_TYPE(cm.mechanism), C.CK_MECHANISM_INFO_PTR(&pInfo)); rv != C.CKR_OK {
		return MechanismInfo{}, fmt.Errorf("get_mechanism_info: 0x%08x : %s", rv, returnValues[rv])
	}
	mi := MechanismInfo{
		MinKeySize: uint(pInfo.ulMinKeySize),
		MaxKeySize: uint(pInfo.ulMaxKeySize),
		Flags:      uint(pInfo.flags),
	}
	return mi, nil
}
