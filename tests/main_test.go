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

// testLabel    = "test_label"
)

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
