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

CK_RV derive_key(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
	return (*fl->C_DeriveKey)(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
}
*/
import "C"
import "fmt"

// Derives a key from a base key, creating a new key object.
func (o *Object) DeriveKey(m *Mechanism, a []*Attribute) (ObjectHandle, error) {
	var newKey C.CK_OBJECT_HANDLE
	attrArena, caa, caalen := cAttribute(a)
	defer attrArena.Free()
	mechArena, mech := cMechanism(m)
	defer mechArena.Free()
	if rv := C.derive_key(o.fl, o.h, mech, o.o, caa, caalen, &newKey); rv != C.CKR_OK {
		return 0, fmt.Errorf("derive_key: 0x%x : %s", rv, returnValues[rv])
	}
	return ObjectHandle(newKey), nil
}
