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

	m.Run()
	slot.Close()
	mod.Close()
}
