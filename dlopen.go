package certex

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>

#cgo linux LDFLAGS: -ldl
#cgo darwin LDFLAGS: -ldl
#cgo openbsd LDFLAGS:
#cgo freebsd LDFLAGS: -ldl
*/
import "C"
import (
	"fmt"
	"unsafe"
)

var libName = "libcertex-rcsp_r.so.1"

// dlOpen tries to get a handle to a library (.so), attempting to access it
// by the names specified in libs and returning the first that is successfully
// opened. Callers are responsible for closing the handler. If no library can
// be successfully opened, an error is returned.
func dlOpen() (unsafe.Pointer, error) {

	cLibName := C.CString(libName)
	defer C.free(unsafe.Pointer(cLibName))

	if p := C.dlopen(cLibName, C.RTLD_LAZY); p != nil {
		return p, nil
	}

	return nil, fmt.Errorf("%s: %s", "dlOpen()", C.GoString(C.dlerror()))
}
