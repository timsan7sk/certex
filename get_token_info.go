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

CK_RV get_token_info(CK_FUNCTION_LIST_PTR fl, CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
	return (*fl->C_GetTokenInfo)(slotID, pInfo);
}
*/
import "C"
import "fmt"

func (s *Slot) getTokenInfo() (C.CK_TOKEN_INFO, error) {
	var cTokenInfo C.CK_TOKEN_INFO
	slotID := C.CK_SLOT_ID(s.id)
	if rv := C.get_token_info(s.fl, slotID, &cTokenInfo); rv != C.CKR_OK {
		return C.CK_TOKEN_INFO{}, fmt.Errorf("GetTokenInfo: 0x%x : %s", rv, returnValues[rv])
	}
	return cTokenInfo, nil
}
