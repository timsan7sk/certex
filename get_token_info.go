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

CK_RV get_token_info(CK_FUNCTION_LIST_PTR fl, CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
	return (*fl->C_GetTokenInfo)(slotID, pInfo);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func (s *Slot) GetTokenInfo() (TokenInfo, error) {
	var cTokenInfo C.CK_TOKEN_INFO
	if rv := C.get_token_info(s.fl, C.CK_SLOT_ID(s.id), &cTokenInfo); rv != C.CKR_OK {
		return TokenInfo{}, fmt.Errorf("GetTokenInfo: 0x%08x : %s", rv, returnValues[rv])
	}
	r := TokenInfo{
		Label:              toString(cTokenInfo.label[:]),
		ManufacturerID:     toString(cTokenInfo.manufacturerID[:]),
		Model:              toString(cTokenInfo.model[:]),
		SerialNumber:       toString(cTokenInfo.serialNumber[:]),
		Flags:              uint(cTokenInfo.flags),
		MaxSessionCount:    uint(cTokenInfo.ulMaxSessionCount),
		SessionCount:       uint(cTokenInfo.ulSessionCount),
		MaxRwSessionCount:  uint(cTokenInfo.ulMaxRwSessionCount),
		RwSessionCount:     uint(cTokenInfo.ulRwSessionCount),
		MaxPinLen:          uint(cTokenInfo.ulMaxPinLen),
		MinPinLen:          uint(cTokenInfo.ulMinPinLen),
		TotalPublicMemory:  uint(cTokenInfo.ulTotalPublicMemory),
		FreePublicMemory:   uint(cTokenInfo.ulFreePrivateMemory),
		TotalPrivateMemory: uint(cTokenInfo.ulTotalPrivateMemory),
		FreePrivateMemory:  uint(cTokenInfo.ulFreePrivateMemory),
		HardwareVersion: Version{
			Major: uint8(cTokenInfo.hardwareVersion.major),
			Minor: uint8(cTokenInfo.hardwareVersion.minor),
		},
		FirmwareVersion: Version{
			Major: uint8(cTokenInfo.firmwareVersion.major),
			Minor: uint8(cTokenInfo.firmwareVersion.minor),
		},
		TimeUTC: toString(cTokenInfo.utcTime[:]),
	}
	C.free(unsafe.Pointer(&cTokenInfo))
	return r, nil
}

func (s *Slot) getTokenInfo() (C.CK_TOKEN_INFO, error) {
	var cTokenInfo C.CK_TOKEN_INFO
	if rv := C.get_token_info(s.fl, C.CK_SLOT_ID(s.id), &cTokenInfo); rv != C.CKR_OK {
		return C.CK_TOKEN_INFO{}, fmt.Errorf("GetTokenInfo: 0x%08x : %s", rv, returnValues[rv])
	}
	return cTokenInfo, nil
}
