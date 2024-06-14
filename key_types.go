package certex

/* Key types: */
var KeyTypes = map[string]uint{
	"CKK_CERTEX_GOST_28147_89": 0x00000001 + CERTEX_DEF_BASE, /* GOST 28147.89 */
	"CKK_CERTEX_RDS":           0x00000002 + CERTEX_DEF_BASE, /* RDS - GOST R 34.10-2001 */
}
