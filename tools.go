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
	"fmt"
	"strings"
	"time"
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

// NewAttribute allocates a Attribute and returns a pointer to it.
// Note that this is merely a convenience function, as values returned
// from the HSM are not converted back to Go values, those are just raw
// byte slices.
func NewAttribute(typ uint, x interface{}) *Attribute {
	// This function nicely transforms *to* an attribute, but there is
	// no corresponding function that transform back *from* an attribute,
	// which in PKCS#11 is just an byte array.
	a := new(Attribute)
	a.Type = typ
	if x == nil {
		return a
	}
	switch v := x.(type) {
	case bool:
		if v {
			a.Value = []byte{1}
		} else {
			a.Value = []byte{0}
		}
	case int:
		a.Value = uintToBytes(uint64(v))
	case int16:
		a.Value = uintToBytes(uint64(v))
	case int32:
		a.Value = uintToBytes(uint64(v))
	case int64:
		a.Value = uintToBytes(uint64(v))
	case uint:
		a.Value = uintToBytes(uint64(v))
	case uint16:
		a.Value = uintToBytes(uint64(v))
	case uint32:
		a.Value = uintToBytes(uint64(v))
	case uint64:
		a.Value = uintToBytes(uint64(v))
	case string:
		a.Value = []byte(v)
	case []byte:
		a.Value = v
	case time.Time: // for CKA_DATE
		a.Value = cDate(v)
	default:
		panic("pkcs11: unhandled attribute type")
	}
	return a
}

// cAttribute returns the start address and the length of an attribute array.
func cAttributeArray(a []*Attribute) (arena, C.CK_ATTRIBUTE_PTR, C.CK_ULONG) {
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

func uintToBytes(x uint64) []byte {
	ul := C.CK_ULONG(x)
	return memBytes(unsafe.Pointer(&ul), unsafe.Sizeof(ul))
}

// memBytes returns a byte slice that references an arbitrary memory area
func memBytes(p unsafe.Pointer, len uintptr) []byte {
	const maxIndex int32 = (1 << 31) - 1
	return (*([maxIndex]byte))(p)[:len:len]
}
func cDate(t time.Time) []byte {
	b := make([]byte, 8)
	year, month, day := t.Date()
	y := fmt.Sprintf("%4d", year)
	m := fmt.Sprintf("%02d", month)
	d1 := fmt.Sprintf("%02d", day)
	b[0], b[1], b[2], b[3] = y[0], y[1], y[2], y[3]
	b[4], b[5] = m[0], m[1]
	b[6], b[7] = d1[0], d1[1]
	return b
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
