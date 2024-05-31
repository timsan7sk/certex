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

CK_RV finalize(CK_FUNCTION_LIST_PTR fl) {
	return (*fl->C_Finalize)(NULL_PTR);
}
*/
import "C"
import "fmt"

func (m *Cryptoki) Close() error {
	rv := C.finalize(m.fl)
	if rv != C.CKR_OK {
		// fmt.Printf("finalize: 0x%x\n", rv)
		return fmt.Errorf("finalize: 0x%x : %s", rv, returnValues[rv])
	}
	if C.dlclose(m.mod) != 0 {
		return fmt.Errorf("dlclose: 0x%x : %s", rv, returnValues[rv])
	}
	return nil
}
