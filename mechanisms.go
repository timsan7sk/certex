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
*/
import "C"

/* Available Certext Mechanisms */
var Mechanisms = map[string]uint{
	/* RSA */
	"CKM_RSA_PKCS_KEY_PAIR_GEN": 0x00000000,
	"CKM_RSA_PKCS":              0x00000001,
	/* GOST 28147.89 */
	"CKM_CERTEX_GOST_28147_89_KEY_GEN": 0x00000000 + CERTEX_DEF_BASE,
	"CKM_CERTEX_GOST_28147_89_ECB":     0x00000001 + CERTEX_DEF_BASE,
	"CKM_CERTEX_GOST_28147_89_OFB":     0x00000002 + CERTEX_DEF_BASE,
	"CKM_CERTEX_GOST_28147_89_CFB":     0x00000003 + CERTEX_DEF_BASE,
	"CKM_CERTEX_GOST_28147_89_MAC":     0x00000004 + CERTEX_DEF_BASE,
	/* Hash for GOST R 34.11-94 / 2012 */
	"CKM_CERTEX_GOSTR3411":         0x0000000A + CERTEX_DEF_BASE, // соответствует  "1.2.398.3.10.1.3.1.1.0"
	"CKM_CERTEX_GOSTR3411_2012_32": 0x00000010 + CERTEX_DEF_BASE, // соответствует  "1.2.398.3.10.1.3.2"
	"CKM_CERTEX_GOSTR3411_2012_64": 0x00000011 + CERTEX_DEF_BASE, // соответствует  "1.2.398.3.10.1.3.3"
	/* GOST R 34.10-2001/2012  keypair generation mechanism */
	"CKM_CERTEX_GOSTR3410_2001_KEY_PAIR_GEN": 0x0000000B + CERTEX_DEF_BASE,
	"CKM_CERTEX_GOSTR3410_2012_KEY_PAIR_GEN": 0x00000012 + CERTEX_DEF_BASE,
	/* GOST R 34.10-2001/2012 'raw' mechanism */
	"CKM_CERTEX_GOSTR3410_2001": 0x0000000C + CERTEX_DEF_BASE, // соответствует "1.2.398.3.10.1.1.1.2"
	"CKM_CERTEX_GOSTR3410_2012": 0x00000013 + CERTEX_DEF_BASE, // соответствует "1.2.398.3.10.1.1.2.3"
	"CKM_CERTEX_GOSTR3410_2015": 0x00000013 + CERTEX_DEF_BASE,
	/* GOST R 34.11-94(2012) hash with GOST R 34.10-2001/2012 mechanism */
	"CKM_CERTEX_GOSTR3411_94_GOSTR3410_2001": 0x0000000D + CERTEX_DEF_BASE,
	"CKM_CERTEX_GOSTR3411_GOSTR3410_2012":    0x00000014 + CERTEX_DEF_BASE,
	"CKM_CERTEX_GOSTR3411_GOSTR3410_2015":    0x00000014 + CERTEX_DEF_BASE,
}
