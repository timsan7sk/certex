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

CK_RV generate_key_pair(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
	return (*fl->C_GenerateKeyPair)(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
}
*/
import "C"
import "fmt"

// Generates a public-key/private-key pair, creating new key objects.
func (s *Slot) GenerateKeyPair(m *Mechanism, public, private []*Attribute) (ObjectHandle, ObjectHandle, error) {
	var (
		pubKey  C.CK_OBJECT_HANDLE
		privKey C.CK_OBJECT_HANDLE
	)
	pubarena, pub, publen := cAttribute(public)
	defer pubarena.Free()
	privarena, priv, privlen := cAttribute(private)
	defer privarena.Free()
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()
	if rv := C.generate_key_pair(s.fl, s.h, mech, pub, publen, priv, privlen, C.CK_OBJECT_HANDLE_PTR(&pubKey), C.CK_OBJECT_HANDLE_PTR(&privKey)); rv != C.CKR_OK {
		return 0, 0, fmt.Errorf("generate_key_pair: 0x%x : %s", rv, returnValues[rv])
	}
	return ObjectHandle(pubKey), ObjectHandle(privKey), nil
}
