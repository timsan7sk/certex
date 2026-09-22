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

CK_RV get_slot_info(CK_FUNCTION_LIST_PTR fl, CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
	return (*fl->C_GetSlotInfo)(slotID, pInfo);
}
*/
import "C"
import "fmt"

// GetSlotInfo obtains information about a particular slot in the system.
// If a token is present, it also fetches the associated token information.
func (s *Slot) GetSlotInfo() (*SlotInfo, error) {
	var cSlotInfo C.CK_SLOT_INFO

	slotID := C.CK_SLOT_ID(s.id)

	if rv := C.get_slot_info(s.fl, slotID, &cSlotInfo); rv != C.CKR_OK {
		return nil, fmt.Errorf("get_slot_info: 0x%08x : %s", rv, returnValues[rv])
	}

	info := SlotInfo{
		Description:    toString(cSlotInfo.slotDescription[:]),
		ManufacturerID: toString(cSlotInfo.manufacturerID[:]),
		Flags:          uint(cSlotInfo.flags),
		HardwareVersion: Version{
			Major: uint8(cSlotInfo.hardwareVersion.major),
			Minor: uint8(cSlotInfo.hardwareVersion.minor),
		},
		FirmwareVersion: Version{
			Major: uint8(cSlotInfo.firmwareVersion.major),
			Minor: uint8(cSlotInfo.firmwareVersion.minor),
		},
	}

	if (cSlotInfo.flags & C.CKF_TOKEN_PRESENT) == 0 {
		return &info, nil
	}

	cTokenInfo, err := internalGetTokenInfo(s.fl, s.id)
	if err != nil {
		return &info, err
	}

	parsedToken := parseTokenInfo(cTokenInfo)
	info.TokenInfo = &parsedToken

	return &info, nil
}
