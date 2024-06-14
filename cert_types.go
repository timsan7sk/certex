package certex

/* Certex HSM certificate*/
var CertTypes = map[string]uint{
	"CKC_CERTEX_HSM_CA":  0x00000001 + CERTEX_DEF_BASE,
	"CKC_CERTEX_HSM_SRV": 0x00000002 + CERTEX_DEF_BASE,
}
