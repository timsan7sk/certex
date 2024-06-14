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

CK_RV get_slot_info(CK_FUNCTION_LIST_PTR fl, CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
	return (*fl->C_GetSlotInfo)(slotID, pInfo);
}
*/
import "C"
import "fmt"

func (s *Slot) GetSlotInfo() (*SlotInfo, error) {
	var cSlotInfo C.CK_SLOT_INFO

	slotID := C.CK_SLOT_ID(s.id)

	if rv := C.get_slot_info(s.fl, slotID, &cSlotInfo); rv != C.CKR_OK {
		return nil, fmt.Errorf("get_slot_info: 0x%x : %s", rv, returnValues[rv])
	}

	info := SlotInfo{
		Description: toString(cSlotInfo.slotDescription[:]),
	}
	if (cSlotInfo.flags & C.CKF_TOKEN_PRESENT) == 0 {
		return &info, nil
	}
	cTokenInfo, err := s.getTokenInfo()
	if err != nil {
		return &info, err
	}
	info.Label = toString(cTokenInfo.label[:])
	info.Model = toString(cTokenInfo.model[:])
	info.Serial = toString(cTokenInfo.serialNumber[:])
	return &info, nil
}
