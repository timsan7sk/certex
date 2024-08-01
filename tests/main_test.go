package tests

import (
	"certex"
	"fmt"
	"os"
	"testing"
)

const (
	algID = 36 // 2012/2015
	// algID   = 21 // 94/2001
	libName = "libcertex-rcsp_r.so.1"
	// Путь до конфига
	confPath = "/home/timsan/Sources/Golang/certex/rcsp.conf"
	// testAdminPIN = ""
	testPIN    = "25032016"
	testSlotID = 0

	testLabel0 = "NUC_TEST_GOST_2015"
	// testLabel1 = "NCA_RSA_TEST"
)

var (
	pubKeyAttrs = []*certex.Attribute{
		certex.NewAttribute(certex.CKA_CLASS, certex.CKO_PUBLIC_KEY),
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_GOST_TEST_KEY_LABEL"),
		certex.NewAttribute(certex.CKA_ID, "TIMSAN_GOST_TEST_KEY_ID"),
		certex.NewAttribute(certex.CKA_KEY_TYPE, certex.CKK_CERTEX_RDS),
		certex.NewAttribute(certex.CKA_VERIFY, true),
		certex.NewAttribute(certex.CKA_TOKEN, false),
		certex.NewAttribute(certex.CKA_PRIVATE, false),
		certex.NewAttribute(certex.CKA_CERTEX_RDS_TYPE, algID),
		certex.NewAttribute(certex.CKA_ENCRYPT, true),
		certex.NewAttribute(certex.CKA_VERIFY_RECOVER, true),
		// certex.NewAttribute(certex.CKA_GOSTR3410_PARAMS, []byte{0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x00}),
		// certex.NewAttribute(certex.CKA_GOSTR3411_PARAMS, []byte{0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02}),
		// certex.NewAttribute(certex.CKA_VALUE, []byte{}),
		// certex.NewAttribute(certex.CKA_VALUE_LEN, 64),
	}
	privKeyAttrs = []*certex.Attribute{
		certex.NewAttribute(certex.CKA_CLASS, certex.CKO_PRIVATE_KEY),
		certex.NewAttribute(certex.CKA_LABEL, "TIMSAN_GOST_TEST_KEY_LABEL"),
		certex.NewAttribute(certex.CKA_ID, "TIMSAN_GOST_TEST_KEY_ID"),
		certex.NewAttribute(certex.CKA_KEY_TYPE, certex.CKK_CERTEX_RDS),
		certex.NewAttribute(certex.CKA_TOKEN, false),
		certex.NewAttribute(certex.CKA_SIGN, true),
		certex.NewAttribute(certex.CKA_PRIVATE, true),
		certex.NewAttribute(certex.CKA_CERTEX_RDS_TYPE, algID),
		certex.NewAttribute(certex.CKA_DECRYPT, true),
		certex.NewAttribute(certex.CKA_DERIVE, true),
		certex.NewAttribute(certex.CKA_SIGN_RECOVER, true),
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
	// mechGOST        = certex.NewMechanism(certex.CKM_RSA_PKCS)
	mechDigGOST = certex.NewMechanism(certex.CKM_CERTEX_GOSTR3411_2012_64)
	mechSigGOST = certex.NewMechanism(certex.CKM_CERTEX_GOSTR3410_2012)

	testData = []byte("TEST_DATA_FOR_TESTS")
)
var (
	mod         *certex.Cryptoki
	slot        *certex.Slot
	testPubKey  certex.Object
	testPrivKey certex.Object
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
	testPubKey, testPrivKey, err = slot.GenerateKeyPair(mechPairGenGOST, pubKeyAttrs, privKeyAttrs)
	if err != nil {
		fmt.Println("Generate Key Pair error: ", err)
		os.Exit(1)
	}
	// objs, _ := slot.FindObjects(fPubKey)
	// for _, o := range objs {
	// 	v, _ := o.Value()
	// 	fmt.Printf("o.Value: %+v\n", v)
	// }
	m.Run()
	_ = testPubKey.DestroyObject()
	_ = testPrivKey.DestroyObject()
	slot.Close()
	mod.Close()
}
