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

CK_RV generate_key(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
	return (*fl->C_GenerateKey)(hSession, pMechanism, pTemplate, ulCount, phKey);
}
*/
import "C"
import "fmt"

// Generates a secret key, creating a new key object.
func (s *Slot) GenerateKey(m *Mechanism, temp []*Attribute) (Object, error) {
	var newKey C.CK_OBJECT_HANDLE
	attrarena, t, tcount := cAttribute(temp)
	defer attrarena.Free()
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()
	if rv := C.generate_key(s.fl, s.h, mech, t, tcount, C.CK_OBJECT_HANDLE_PTR(&newKey)); rv != C.CKR_OK {
		return Object{}, fmt.Errorf("generate_key: 0x%x : %s", rv, returnValues[rv])
	}
	key, err := s.newObject(newKey)
	if err != nil {
		return Object{}, err
	}
	return key, nil
}
