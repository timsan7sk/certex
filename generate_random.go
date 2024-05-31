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

CK_RV generate_random(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR *RandomData, CK_ULONG ulRandomLen) {
	*RandomData = calloc(ulRandomLen, sizeof(CK_BYTE));
	if (*RandomData == NULL) {
		return CKR_HOST_MEMORY;
	}
	return (*fl->C_GenerateRandom)(hSession, *RandomData, ulRandomLen);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func (s *Slot) GenerateRandom(length int) ([]byte, error) {
	var rand C.CK_BYTE_PTR
	if rv := C.generate_random(s.fl, s.h, &rand, C.CK_ULONG(length)); rv != C.CKR_OK {
		return nil, fmt.Errorf("GenerateRandom: 0x%x", rv)
	}
	r := C.GoBytes(unsafe.Pointer(rand), C.int(length))
	C.free(unsafe.Pointer(rand))
	return r, nil
}
