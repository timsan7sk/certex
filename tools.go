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

static inline void putAttributePval(CK_ATTRIBUTE_PTR a, CK_VOID_PTR pValue) {
	a->pValue = pValue;
}

static inline void putMechanismParam(CK_MECHANISM_PTR m, CK_VOID_PTR pParameter) {
	m->pParameter = pParameter;
}

CK_ULONG Index(CK_ULONG_PTR array, CK_ULONG i) {
	return array[i];
}
*/
import "C"
import (
	"strings"
	"unsafe"
)

// cAttribute returns the start address and the length of an attribute slice.
func cAttribute(a []*Attribute) (arena, C.CK_ATTRIBUTE_PTR, C.CK_ULONG) {
	var arena arena
	if len(a) == 0 {
		return nil, nil, 0
	}
	pa := make([]C.CK_ATTRIBUTE, len(a))
	for i, attr := range a {
		pa[i]._type = C.CK_ATTRIBUTE_TYPE(attr.Type)
		if len(attr.Value) != 0 {
			buf, len := arena.Allocate(attr.Value)
			// field is unaligned on windows so this has to call into C
			C.putAttributePval(&pa[i], buf)
			pa[i].ulValueLen = len
		}
	}
	return arena, &pa[0], C.CK_ULONG(len(a))
}

// ckString converts a Go string to a cryptokit string. The string is still held
// by Go memory and doesn't need to be freed.
func ckString(s string) []C.CK_UTF8CHAR {
	b := make([]C.CK_UTF8CHAR, len(s))
	for i, c := range []byte(s) {
		b[i] = C.CK_UTF8CHAR(c)
	}
	return b
}

// ckCString converts a Go string to a cryptokit string held by C. This is required,
// for example, when building a CK_ATTRIBUTE, which needs to hold a pointer to a
// cryptokit string.
//
// This method also returns a function to free the allocated C memory.
func ckCString(s string) (cstring *C.CK_UTF8CHAR, free func()) {
	b := (*C.CK_UTF8CHAR)(C.malloc(C.sizeof_CK_UTF8CHAR * C.ulong(len(s))))
	bs := unsafe.Slice(b, len(s))
	for i, c := range []byte(s) {
		bs[i] = C.CK_UTF8CHAR(c)
	}
	return b, func() { C.free(unsafe.Pointer(b)) }
}

func ckGoString(s *C.CK_UTF8CHAR, n C.CK_ULONG) string {
	var sb strings.Builder
	sli := unsafe.Slice(s, n)
	for _, b := range sli {
		sb.WriteByte(byte(b))
	}
	return sb.String()
}

func toString(b []C.uchar) string {
	lastIndex := len(b)
	for i := len(b); i > 0; i-- {
		if b[i-1] != C.uchar(' ') {
			break
		}
		lastIndex = i - 1
	}

	var sb strings.Builder
	for _, c := range b[:lastIndex] {
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

// ckStringPadded copies a string into b, padded with ' '. If the string is larger
// than the provided buffer, this function returns false.
func ckStringPadded(b []C.CK_UTF8CHAR, s string) bool {
	if len(s) > len(b) {
		return false
	}
	for i := range b {
		if i < len(s) {
			b[i] = C.CK_UTF8CHAR(s[i])
		} else {
			b[i] = C.CK_UTF8CHAR(' ')
		}
	}
	return true
}

// toSlice converts from a C style array to a []uint.
func toSlice(cArray C.CK_ULONG_PTR, size C.CK_ULONG) []uint {
	s := make([]uint, int(size))
	for i := 0; i < len(s); i++ {
		s[i] = uint(C.Index(cArray, C.CK_ULONG(i)))
	}
	C.free(unsafe.Pointer(cArray))
	return s
}
func toGoBytes(data []C.CK_BYTE) []byte {
	goBytes := make([]byte, len(data))
	for i, b := range data {
		goBytes[i] = byte(b)
	}
	return goBytes
}

func toCBytes(data []byte) []C.CK_BYTE {
	cBytes := make([]C.CK_BYTE, len(data))
	for i, b := range data {
		cBytes[i] = C.CK_BYTE(b)
	}
	return cBytes
}

// Returns the pointer/length pair corresponding to data.
func cData(data []byte) (pData C.CK_BYTE_PTR) {
	l := len(data)
	if l == 0 {
		// &data[0] is forbidden in this case, so use a nontrivial array instead.
		data = []byte{0}
	}
	return C.CK_BYTE_PTR(unsafe.Pointer(&data[0]))
}

// NewMechanism returns a pointer to an initialized Mechanism.
func NewMechanism(mech uint) *Mechanism {
	m := new(Mechanism)
	m.Mechanism = mech
	return m
}
func cMechanism(mech *Mechanism) (arena, *C.CK_MECHANISM) {
	cmech := &C.CK_MECHANISM{mechanism: C.CK_MECHANISM_TYPE(mech.Mechanism)}
	param := mech.Parameter
	var arena arena
	if len(param) != 0 {
		buf, len := arena.Allocate(param)
		// field is unaligned on windows so this has to call into C
		C.putMechanismParam(cmech, buf)
		cmech.ulParameterLen = len
	}
	return arena, cmech
}
