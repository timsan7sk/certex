package tests

import (
	"certex"
	"fmt"
	"os"
	"testing"
)

const (
	libName = "libcertex-rcsp_r.so.1"

	// testAdminPIN = ""
	testPIN    = "25032016"
	testSlotID = 0

// testLabel    = "test_label"
)

var (
	mod  *certex.Cryptoki
	slot *certex.Slot
)

func TestMain(m *testing.M) {
	var err error
	mod, err = certex.Open(libName)
	if err != nil {
		fmt.Println("Open module error: ", err)
		os.Exit(1)
	}
	// // ml, _ := mod.GetMechanismList(0)
	// // for i, m := range ml {
	// // 	mInfo, _ := mod.GetMechanismInfo(0, m)
	// // 	fmt.Printf("%d - mInfo: %+v\n", i, mInfo)
	// // }
	opts := certex.Options{
		PIN:       testPIN,
		ReadWrite: false,
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
	// // err = slot.SetPIN("25032016", "00000000")
	// // if err != nil {
	// // 	fmt.Printf("%s\n", err)
	// // }
	// // for k, v := range certex.MechanismMap {
	// // 	fmt.Printf("key[%s] value[%x]\n", k, v)
	// // }

	// // fmt.Printf("slot: %+v\n", slot)
	// // slotInfo, _ := slot.GetSlotInfo(0)
	// // fmt.Printf("slotInfo: %+v\n", slotInfo)
	// // sInfo, _ := slot.GetSessionInfo()
	// // fmt.Printf("sInfo: %+v\n", sInfo)
	// // tokenInfo, _ := slot.GetTokenInfo(0)
	// // fmt.Printf("tokenInfo: %+v\n", tokenInfo)
	// var fltr = certex.Filter{
	// 	Class: certex.ClassPrivateKey,
	// 	Label: "",
	// }
	// objSlice, _ := slot.FindObjects(fltr)
	// mech := certex.Mechanism{
	// 	Mechanism: certex.MechanismMap["CKM_CERTEX_GOSTR3411_GOSTR3410_2015"],
	// 	Parameter: nil,
	// }
	// for _, o := range objSlice {
	// 	l, _ := o.Label()
	// 	fmt.Printf("l: %+v - c: %s\n", l, o.Class().String())
	// 	if l == "NUC_TEST_GOST_2015" {
	// 		// d, _ := base64.StdEncoding.DecodeString("0hu3jfUz5sAyvv1QzLEjvrM8GIUwpD6m20xTBKsevJ3ll4JHdaTx4vtLSXM0Vd7Avgj1j8zcuivK2JFHKAR1wA==")
	// 		d, _ := base64.StdEncoding.DecodeString("RSPRqNtPvrjBwUMWgTUUqfkz2bMXrYB3akNQMwQdSRNUunhugNAnBzjZBg6HUh2TxjbPf7rbqTFrLU2bjC9An9NScz60qcDU7TQnDYUu1i0GPrVawCvHhfpziE2UJ3Bi")
	// 		// d := []byte("RSPRqNtPvrjBwUMWgTUUqfkz2bMXrYB3akNQMwQdSRNUunhugNAnBzjZBg6HUh2TxjbPf7rbqTFrLU2bjC9An9NScz60qcDU7TQnDYUu1i0GPrVawCvHhfpziE2UJ3Bi")
	// 		if err := o.SignInit(&mech); err != nil {
	// 			fmt.Printf("%+v\n", err)
	// 		} else {
	// 			if e := o.SignUpdate(d); e != nil {
	// 				fmt.Printf("%+v\n", e)
	// 			} else {
	// 				s, e := o.SignFinal(d)
	// 				if e != nil {
	// 					fmt.Printf("%+v\n", e)
	// 				} else {
	// 					fmt.Printf("GOTCHA!!!\n")
	// 					fmt.Printf("s: %s\n", s)
	// 					fmt.Printf("s: %s\n", base64.StdEncoding.EncodeToString(s))
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	m.Run()
	slot.CloseAll()
	mod.Close()
}
