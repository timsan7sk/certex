package tests

import (
	"fmt"
	"os"
	"testing"

	"github.com/timsan7sk/certex"
)

const (
	algID = 36 // 2012/2015
	// algID   = 21 // 94/2001
	libName = "libcertex-rcsp_r.so.1"
	// Путь до конфига
	confPath = "/etc/rcsp.conf"
	// testAdminPIN = ""
	testPIN    = "25032016"
	testSlotID = 0

	testLabel0 = "NUC_TEST_GOST_2015"
	// testLabel1 = "NCA_RSA_TEST"
)

var (
	certAttrs = []*certex.Attribute{
		certex.NewAttribute(certex.CKA_CLASS, certex.CKO_CERTIFICATE),
		certex.NewAttribute(certex.CKA_CERTIFICATE_TYPE, certex.CKC_X_509),
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_TEST_CERT_OBJECT"),
		certex.NewAttribute(certex.CKA_SUBJECT, "TIMSAN_TEST_CERT_OBJECT"),
		certex.NewAttribute(certex.CKA_VALUE, "TIMSAN_TEST_VALUE_DATA"),
	}
	dataAttrs = []*certex.Attribute{
		certex.NewAttribute(certex.CKA_CLASS, certex.CKO_DATA),
		certex.NewAttribute(certex.CKA_TOKEN, false),
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_TEST_DATA_OBJECT"),
		certex.NewAttribute(certex.CKA_APPLICATION, "TIMSAN_TEST_AN_APPLICATION"),
		certex.NewAttribute(certex.CKA_VALUE, "TIMSAN_TEST_VALUE_DATA"),
	}
	copyAttrs = []*certex.Attribute{
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_TEST_DATA_OBJECT_COPY"),
		certex.NewAttribute(certex.CKA_APPLICATION, "TIMSAN_TEST_AN_APPLICATION_COPY"),
		certex.NewAttribute(certex.CKA_VALUE, "TIMSAN_TEST_VALUE_DATA_COPY"),
	}
	pubKeyAttrs = []*certex.Attribute{
		certex.NewAttribute(certex.CKA_CLASS, certex.CKO_PUBLIC_KEY),
		// certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_GOST_TEST_KEY_LABEL"),
		// certex.NewAttribute(certex.CKA_ID, "TIMSAN_GOST_TEST_KEY_ID"),
		// certex.NewAttribute(certex.CKA_KEY_TYPE, certex.CKK_CERTEX_RDS),
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_RSA_TEST_KEY_LABEL"),
		certex.NewAttribute(certex.CKA_ID, "TIMSAN_RSA_TEST_KEY_ID"),
		certex.NewAttribute(certex.CKA_KEY_TYPE, certex.CKK_RSA),
		certex.NewAttribute(certex.CKA_VERIFY, true),
		certex.NewAttribute(certex.CKA_TOKEN, true),
		certex.NewAttribute(certex.CKA_PRIVATE, false),
		// certex.NewAttribute(certex.CKA_CERTEX_RDS_TYPE, algID),
		certex.NewAttribute(certex.CKA_ENCRYPT, true),
		// certex.NewAttribute(certex.CKA_VERIFY_RECOVER, true),
		certex.NewAttribute(certex.CKA_MODULUS_BITS, 2048),
		certex.NewAttribute(certex.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		// certex.NewAttribute(certex.CKA_WRAP, false),
		// certex.NewAttribute(certex.CKA_GOSTR3410_PARAMS, []byte{0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x00}),
		// certex.NewAttribute(certex.CKA_GOSTR3411_PARAMS, []byte{0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02}),
		// certex.NewAttribute(certex.CKA_VALUE, []byte{}),
		// certex.NewAttribute(certex.CKA_VALUE_LEN, 64),
	}
	privKeyAttrs = []*certex.Attribute{
		certex.NewAttribute(certex.CKA_CLASS, certex.CKO_PRIVATE_KEY),
		// certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_GOST_TEST_KEY_LABEL"),
		// certex.NewAttribute(certex.CKA_ID, "TIMSAN_GOST_TEST_KEY_ID"),
		// certex.NewAttribute(certex.CKA_KEY_TYPE, certex.CKK_CERTEX_RDS),
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_RSA_TEST_KEY_LABEL"),
		certex.NewAttribute(certex.CKA_ID, "TIMSAN_RSA_TEST_KEY_ID"),
		certex.NewAttribute(certex.CKA_KEY_TYPE, certex.CKK_RSA),
		certex.NewAttribute(certex.CKA_TOKEN, true),
		certex.NewAttribute(certex.CKA_SIGN, true),
		certex.NewAttribute(certex.CKA_DECRYPT, true),
		certex.NewAttribute(certex.CKA_PRIVATE, true),
		// certex.NewAttribute(certex.CKA_CERTEX_RDS_TYPE, ),
		// certex.NewAttribute(certex.CKA_CERTEX_RDS_TYPE, algID),
		certex.NewAttribute(certex.CKA_SENSITIVE, true),
		// certex.NewAttribute(certex.CKA_WRAP_WITH_TRUSTED, false),
		// certex.NewAttribute(certex.CKA_UNWRAP, false),
		certex.NewAttribute(certex.CKA_EXTRACTABLE, true),
		// certex.NewAttribute(certex.CKA_DECRYPT, true),
		// certex.NewAttribute(certex.CKA_DERIVE, true),
		// certex.NewAttribute(certex.CKA_SIGN_RECOVER, true),
		// certex.NewAttribute(certex.CKA_END_DATE, time.Now().Local()),
		// certex.NewAttribute(certex.CKA_GOSTR3410_PARAMS, []byte{0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x00}),
		// certex.NewAttribute(certex.CKA_GOSTR3411_PARAMS, []byte{0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02}),
		// certex.NewAttribute(certex.CKA_VALUE, []byte{}),
		// certex.NewAttribute(certex.CKA_VALUE_LEN, 64),
	}
	secKeyAttrs = []*certex.Attribute{
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_AES_TEST_KEY"),
		certex.NewAttribute(certex.CKA_TOKEN, false),
		certex.NewAttribute(certex.CKA_ENCRYPT, true),
		certex.NewAttribute(certex.CKA_DECRYPT, true),
		certex.NewAttribute(certex.CKA_SENSITIVE, true),
		certex.NewAttribute(certex.CKA_EXTRACTABLE, true),
		certex.NewAttribute(certex.CKA_VALUE_LEN, 16),
	}
	mechKeyGenAES   = certex.NewMechanism(certex.CKM_AES_KEY_GEN)
	mechPairGenGOST = certex.NewMechanism(certex.CKM_CERTEX_GOSTR3410_2012_KEY_PAIR_GEN)
	mechPairGenRSA  = certex.NewMechanism(certex.CKM_RSA_PKCS_KEY_PAIR_GEN)
	mechDigSHA      = certex.NewMechanism(certex.CKM_SHA256)
	mechDigGOST     = certex.NewMechanism(certex.CKM_CERTEX_GOSTR3411_2012_64)
	mechSigGOST     = certex.NewMechanism(certex.CKM_CERTEX_GOSTR3410_2012)

	testData = []byte("TEST_DATA_FOR_TESTS")
)
var (
	mod         *certex.Cryptoki
	slot        *certex.Slot
	testPubKey  certex.Object
	testPrivKey certex.Object
	testSecKey  certex.Object
)

func TestMain(m *testing.M) {
	var err error
	mod, err = certex.Open(libName, confPath)
	if err != nil {
		fmt.Println("Open module error: ", err)
		os.Exit(1)
	}
	mod.Lock()
	defer mod.Unlock()

	opts := certex.Options{
		PIN:       testPIN,
		ReadWrite: true,
	}
	slot, err = mod.Slot(testSlotID, opts)
	if err != nil {
		fmt.Println("Open slot error: ", err)
		os.Exit(1)
	}
	testPubKey, testPrivKey, err = slot.GenerateKeyPair(mechPairGenRSA, pubKeyAttrs, privKeyAttrs)
	if err != nil {
		fmt.Println("Generate Key Pair error: ", err)
		// os.Exit(1)
	}
	testSecKey, err = slot.GenerateKey(mechKeyGenAES, secKeyAttrs)
	if err != nil {
		fmt.Println("Generate Key error: ", err)
		// os.Exit(1)
	}
	// attr, err := testPubKey.Attribute(certex.CKA_KEY_TYPE)
	// if err != nil {
	// 	fmt.Println("Attribute: ", err)
	// }
	// fmt.Println(attr)
	x := m.Run()

	if err := testPubKey.DestroyObject(); err != nil {
		fmt.Println(err)
	}
	err = testPrivKey.DestroyObject()
	if err != nil {
		fmt.Println(err)
	}
	err = testSecKey.DestroyObject()
	if err != nil {
		fmt.Println(err)
	}
	if err := slot.Close(); err != nil {
		fmt.Println(err)
	}
	if err := mod.Close(); err != nil {
		fmt.Println(err)

	}
	os.Exit(x)
}
