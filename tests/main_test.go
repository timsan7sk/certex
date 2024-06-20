package tests

import (
	"certex"
	"fmt"
	"os"
	"testing"
)

const (
	libName = "libcertex-rcsp_r.so.1"
	// Путь до конфига
	confPath = "/home/timsan/Sources/Golang/Certex/rcsp.conf"
	// testAdminPIN = ""
	testPIN    = "25032016"
	testSlotID = 0

	testLabel0 = "NUC_TEST_GOST_2015"
	testLabel1 = "NCA_RSA_TEST"
)

var digMech = certex.Mechanism{
	Mechanism: certex.Mechanisms["CKM_CERTEX_GOSTR3411_2012_64"],
	Parameter: nil,
}
var sMech = certex.Mechanism{
	Mechanism: certex.Mechanisms["CKM_CERTEX_GOSTR3410_2012"],
	Parameter: nil,
}
var srMech = certex.Mechanism{
	Mechanism: certex.Mechanisms["CKM_RSA_PKCS"],
	Parameter: nil,
}
var suMech = certex.Mechanism{
	Mechanism: certex.Mechanisms["CKM_CERTEX_GOSTR3410_2001"],
	Parameter: nil,
}

var (
	mod  *certex.Cryptoki
	slot *certex.Slot
)

func TestMain(m *testing.M) {
	var err error
	mod, err = certex.Open(libName, confPath)
	if err != nil {
		fmt.Println("Open module error: ", err)
		os.Exit(1)
	}
	opts := certex.Options{
		PIN:       testPIN,
		ReadWrite: true,
	}
	slot, err = mod.Slot(testSlotID, opts)
	if err != nil {
		fmt.Println("Open slot error: ", err)
		os.Exit(1)
	}
	// // sopt := certex.SlotOptions{
	// // 	AdminPIN: "25032016",
	// // 	PIN:      "25032016",
	// // 	Label:    "Test_Label",
	// // }
	// // slotList, _ := mod.GetSlotList()
	// // fmt.Printf("slotList: %+v\n", slotList)
	// // if err := mod.InitToken(0, sopt); err != nil {
	// // 	fmt.Printf("%s\n", err)
	// // }

	m.Run()
	slot.Close()
	mod.Close()
}
