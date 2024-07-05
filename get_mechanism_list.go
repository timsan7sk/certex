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

CK_RV get_mechanism_list(CK_FUNCTION_LIST_PTR fl, CK_ULONG slotID, CK_ULONG_PTR *pMechanismList, CK_ULONG_PTR pulCount) {
	CK_RV rv =(*fl->C_GetMechanismList)((CK_SLOT_ID) slotID, NULL, pulCount);
	// Gemaltos PKCS11 implementation returns CKR_BUFFER_TOO_SMALL on a NULL ptr instad of CKR_OK as the spec states.
	if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
		return rv;
	}
	*pMechanismList = calloc(*pulCount, sizeof(CK_MECHANISM_TYPE));
	rv = (*fl->C_GetMechanismList)((CK_SLOT_ID) slotID, (CK_MECHANISM_TYPE_PTR) * pMechanismList, pulCount);
	return rv;
}
*/
import "C"
import (
	"fmt"
)

// GetMechanismList obtains a list of mechanism types supported by a token.
func (m *Cryptoki) GetMechanismList(slotID uint) ([]*Mechanism, error) {
	var (
		pMechanismList C.CK_ULONG_PTR
		pulCount       C.CK_ULONG
	)
	if rv := C.get_mechanism_list(m.fl, C.CK_ULONG(slotID), &pMechanismList, &pulCount); rv != C.CKR_OK {
		return nil, fmt.Errorf("GetMechanismList: 0x%08x : %s", rv, returnValues[rv])

	}
	ml := make([]*Mechanism, int(pulCount))
	for i, typ := range toSlice(pMechanismList, pulCount) {
		ml[i] = NewMechanism(typ)
	}

	return ml, nil
}
