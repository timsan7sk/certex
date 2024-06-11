package certex

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>

#include "./headers/cryptoki.h"
#include "./headers/pkcs11def.h"
#include "./headers/pkcs11t.h"
#include "./headers/PKICertexHSM.h"


*/
// #cgo linux LDFLAGS: -ldl
// #cgo darwin LDFLAGS: -ldl
// #cgo openbsd LDFLAGS:
// #cgo freebsd LDFLAGS: -ldl
import "C"
import (
	"fmt"
	"os"
)

func Open(libName string) (*Cryptoki, error) {

	mod, err := dlOpen(libName)
	if err != nil {
		fmt.Printf("dlOpen: %s\n", err)
		os.Exit(1)
	}
	connect(mod)

	var p C.CK_FUNCTION_LIST_PTR

	// fmt.Printf("p: %v\n", p)
	// fmt.Printf("mod: %d\n", mod)

	p, err = getFunctionList(mod, p)
	if err != nil {
		fmt.Printf("getFunctionList: %s\n", err)
	}
	if err := initialize(p); err != nil {
		fmt.Printf("initialize: %s\n", err)
	}
	info, err := getInfo(p)

	if err != nil {
		fmt.Printf("getInfo: %s\n", err)
	}
	return &Cryptoki{
		mod:     mod,
		fl:      p,
		version: info.cryptokiVersion,
		info: Info{
			Manufacturer: string(info.manufacturerID[:]),
			Version: Version{
				Major: uint8(info.libraryVersion.major),
				Minor: uint8(info.libraryVersion.minor),
			},
			Description: string(info.libraryDescription[:]),
		},
	}, nil
}
