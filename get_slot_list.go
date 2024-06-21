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

CK_RV get_slot_list(CK_FUNCTION_LIST_PTR fl, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
	return (*fl->C_GetSlotList)(CK_FALSE, pSlotList, pulCount);
}

*/
import "C"
import "fmt"

func (m *Cryptoki) GetSlotList() ([]uint32, error) {
	var n C.CK_ULONG
	if rv := C.get_slot_list(m.fl, nil, &n); rv != C.CKR_OK {
		return nil, fmt.Errorf("get_slot_list: 0x%x : %s", rv, returnValues[rv])
	}

	l := make([]C.CK_SLOT_ID, int(n))
	if rv := C.get_slot_list(m.fl, &l[0], &n); rv != C.CKR_OK {
		return nil, fmt.Errorf("get_slot_list: 0x%x : %s", rv, returnValues[rv])
	}
	if int(n) > len(l) {
		return nil, fmt.Errorf("C_GetSlotList returned too many elements, got %d, want %d", int(n), len(l))
	}
	l = l[:int(n)]

	ids := make([]uint32, len(l))
	for i, id := range l {
		ids[i] = uint32(id)
	}
	return ids, nil
}
