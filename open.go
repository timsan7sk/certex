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
import "C"
import (
	"fmt"
)

// Open загружает динамическую библиотеку PKCS#11, инициализирует коннектор и выполняет C_Initialize.
func Open(libName string, confPath string) (*Cryptoki, error) {
	mod, err := dlOpen(libName)
	if err != nil {
		return nil, fmt.Errorf("dlOpen: %w", err)
	}

	// Подключаем конфигурационный файл провайдера через rcsp_connect.
	connect(mod, confPath)

	var p C.CK_FUNCTION_LIST_PTR
	p, err = getFunctionList(mod, p)
	if err != nil {
		return nil, fmt.Errorf("getFunctionList: %w", err)
	}

	if err := initialize(p); err != nil {
		return nil, err
	}

	info, err := getInfo(p)
	if err != nil {
		return nil, fmt.Errorf("getInfo: %w", err)
	}

	return &Cryptoki{
		mod:     mod,
		fl:      p,
		version: info.cryptokiVersion,
		info: Info{
			Manufacturer: toString(info.manufacturerID[:]),
			Version: Version{
				Major: uint8(info.libraryVersion.major),
				Minor: uint8(info.libraryVersion.minor),
			},
			Description: toString(info.libraryDescription[:]),
		},
	}, nil
}
