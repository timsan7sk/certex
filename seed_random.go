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

CK_RV seed_random(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
	return (*fl->C_SeedRandom)(hSession, pSeed, ulSeedLen);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func (s *Slot) SeedRandom(seed []byte) error {
	if rv := C.seed_random(s.fl, s.h, C.CK_BYTE_PTR(unsafe.Pointer(&seed[0])), C.CK_ULONG(len(seed))); rv != C.CKR_OK {
		return fmt.Errorf("SeedRandom: 0x%08x", rv)
	}
	return nil
}
