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
)

// GetTokenInfo obtains information about a particular token in the system
// without requiring an active session.
func (m *Cryptoki) GetTokenInfo(slotID uint32) (*TokenInfo, error) {
	cTokenInfo, err := internalGetTokenInfo(m.fl, slotID)
	if err != nil {
		return nil, err
	}
	info := parseTokenInfo(cTokenInfo)
	return &info, nil
}

// internalGetTokenInfo safely wraps the underlying C_GetTokenInfo CGO call
// using the provided cryptographic function list pointer.
func internalGetTokenInfo(fl C.CK_FUNCTION_LIST_PTR, slotID uint32) (C.CK_TOKEN_INFO, error) {
	var cTokenInfo C.CK_TOKEN_INFO
	if rv := C.get_token_info(fl, C.CK_SLOT_ID(slotID), &cTokenInfo); rv != C.CKR_OK {
		return C.CK_TOKEN_INFO{}, fmt.Errorf("GetTokenInfo: 0x%08x : %s", rv, returnValues[rv])
	}
	return cTokenInfo, nil
}

// parseTokenInfo maps the native C.CK_TOKEN_INFO structure to the Go TokenInfo representation.
func parseTokenInfo(cTokenInfo C.CK_TOKEN_INFO) TokenInfo {
	return TokenInfo{
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
		FreePublicMemory:   uint(cTokenInfo.ulFreePublicMemory),
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
}
