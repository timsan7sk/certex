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

typedef void (* D_rcsp_connect)(char*);
static void connect(D_rcsp_connect f, char* path) { f(path); }
*/
import "C"
import (
	"unsafe"
)

// Путь до конфига
var path = "/home/timsan/Sources/Golang/Certex/rcsp.conf"

// Connect to the HSM
func connect(p unsafe.Pointer) {

	cCon := C.CString("rcsp_connect")
	defer C.free(unsafe.Pointer(cCon))

	cConFn := (C.D_rcsp_connect)(C.dlsym(p, cCon))
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	C.connect(cConFn, cPath)
}
