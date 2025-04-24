package certex

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>

#include "cryptoki.h"
#include "pkcs11def.h"
#include "pkcs11t.h"
#include "PKICertexHSM.h"


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

// Opens Cryptoki module
func Open(libName string, confPath string) (*Cryptoki, error) {

	mod, err := dlOpen(libName)
	if err != nil {
		fmt.Printf("dlOpen: %s\n", err)
		os.Exit(1)
	}
	connect(mod, confPath)

	var p C.CK_FUNCTION_LIST_PTR

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
