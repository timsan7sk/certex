package tests

import (
	"certex"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	mod, err := certex.Open()
	if err != nil {
		fmt.Println("New module open error", err)
		os.Exit(1)
	}
	// ml, _ := mod.GetMechanismList(0)
	// for i, m := range ml {
	// 	mInfo, _ := mod.GetMechanismInfo(0, m)
	// 	fmt.Printf("%d - mInfo: %+v\n", i, mInfo)
	// }
	opts := certex.Options{
		PIN:       "25032016",
		ReadWrite: false,
	}
	// slotList, _ := mod.GetSlotList()
	// fmt.Printf("slotList: %+v\n", slotList)

	slot, _ := mod.Slot(uint(0), opts)
	// err = slot.SetPIN("25032016", "00000000")
	// if err != nil {
	// 	fmt.Printf("%s\n", err)
	// }
	// for k, v := range certex.MechanismMap {
	// 	fmt.Printf("key[%s] value[%x]\n", k, v)
	// }

	// fmt.Printf("slot: %+v\n", slot)
	// slotInfo, _ := slot.GetSlotInfo(0)
	// fmt.Printf("slotInfo: %+v\n", slotInfo)
	// sInfo, _ := slot.GetSessionInfo()
	// fmt.Printf("sInfo: %+v\n", sInfo)
	// tokenInfo, _ := slot.GetTokenInfo(0)
	// fmt.Printf("tokenInfo: %+v\n", tokenInfo)
	var fltr = certex.Filter{
		Class: certex.ClassPrivateKey,
		Label: "",
	}
	objSlice, _ := slot.FindObjects(fltr)
	mech := certex.Mechanism{
		Mechanism: certex.MechanismMap["CKM_CERTEX_GOSTR3411_GOSTR3410_2015"],
		Parameter: nil,
	}
	for _, o := range objSlice {
		l, _ := o.Label()
		// fmt.Printf("l: %+v - c: %s\n", l, o.Class().String())
		if l == "NCA_GOST_TEST" {
			d, _ := base64.StdEncoding.DecodeString("vJ0tWWPe0ZyIwcNm+HlpozYKnz0XYommpwIuIeFnBMDafffimYsCoXDAnTpq0/ka/jf5Db1ArFcAZuTKtQFoyw==ASAsASASAAsasasdasdasdasfawefwafscasca")
			if err := o.SignRecoverInit(&mech); err != nil {
				fmt.Printf("%+v\n", err)
			} else {
				if s, e := o.SignRecover(d); e != nil {
					fmt.Printf("%+v\n", e)
				} else {
					fmt.Printf("GOTCHA!!!\n")
					fmt.Printf("s: %s\n", s)
					fmt.Printf("s: %s\n", base64.StdEncoding.EncodeToString(s))
				}
			}
		}
	}

	// m.Run()
	defer mod.Close()
}
