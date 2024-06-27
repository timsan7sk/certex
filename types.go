package certex

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "./headers/cryptoki.h"
#include "./headers/pkcs11def.h"
#include "./headers/pkcs11t.h"
#include "./headers/PKICertexHSM.h"

*/
import "C"
import (
	"unsafe"
)

type arena []unsafe.Pointer

func (a *arena) Allocate(obj []byte) (C.CK_VOID_PTR, C.CK_ULONG) {
	cobj := C.calloc(C.size_t(len(obj)), 1)
	*a = append(*a, cobj)
	C.memmove(cobj, unsafe.Pointer(&obj[0]), C.size_t(len(obj)))
	return C.CK_VOID_PTR(cobj), C.CK_ULONG(len(obj))
}

func (a arena) Free() {
	for _, p := range a {
		C.free(p)
	}
}

// Holds an attribute type/value combination.
type Attribute struct {
	Type  uint
	Value []byte
}

// Hold options for returning a subset of objects from a slot.
//
// The returned object will match all provided parameters. For example, if
// Class=ClassPrivateKey and Label="foo", the returned object must be a
// private key with label "foo".
type Filter struct {
	Class Class
	Label string
}

// Holds global information about the module.
type Info struct {
	// Manufacturer of the implementation. When multiple PKCS #11 devices are
	// present this is used to differentiate devices.
	Manufacturer string
	// Version of the module.
	Version Version
	// Human readable description of the module.
	Description string
}

// Holds a major and minor version.
type Version struct {
	Major uint8
	Minor uint8
}

type Cryptoki struct {
	// Pointer to the dlopen handle. Kept around to dlfree
	// when the Module is closed.
	mod unsafe.Pointer
	// List of C functions provided by the module.
	fl C.CK_FUNCTION_LIST_PTR
	// Version of the module, used for compatibility.
	version C.CK_VERSION
	// Holds global information about the module.
	info Info
}

// Holds an mechanism type/value combination.
type Mechanism struct {
	Mechanism uint
	Parameter []byte
}

// Provides information about a particular mechanism.
type MechanismInfo struct {
	MinKeySize uint
	MaxKeySize uint
	Flags      uint
}

// Represents a single object stored within a slot. For example a key or
// certificate.
type Object struct {
	p
	o C.CK_OBJECT_HANDLE
	c C.CK_OBJECT_CLASS
}
type p struct {
	fl C.CK_FUNCTION_LIST_PTR
	h  C.CK_SESSION_HANDLE
}

// Returns the type of the object stored. For example, certificate, public
// key, or private key.
func (o Object) Class() Class {
	return Class(int(o.c))
}

// SessionInfo provides information about a session.
type SessionInfo struct {
	SlotID      uint
	State       uint
	Flags       uint
	DeviceError uint
}

// Represents a session to a slot.
//
// A session holds a listable set of objects, such as certificates and
// cryptographic keys.
type Slot struct {
	p
	rw bool
	id uint32
}

// Holds the SlotID which for which an slot event (token insertion,
// removal, etc.) occurred.
type SlotEvent struct {
	SlotID uint
}

type SlotOptions struct {
	AdminPIN string
	PIN      string
	Label    string
}

// Holds information about the slot and underlying token.
type SlotInfo struct {
	Label       string
	Model       string
	Serial      string
	Description string
}

// Holds configuration options for the slot session.
type Options struct {
	PIN      string
	AdminPIN string
	// Indicates that the slot should be opened with write capabilities,
	// such as generating keys or importing certificates.
	//
	// By default, sessions can access objects and perform signing requests.
	ReadWrite bool
}

// Obtains information about a particular token
type TokenInfo struct {
	Label              string
	ManufacturerID     string
	Model              string
	SerialNumber       string
	Flags              uint
	MaxSessionCount    uint
	SessionCount       uint
	MaxRwSessionCount  uint
	RwSessionCount     uint
	MaxPinLen          uint
	MinPinLen          uint
	TotalPublicMemory  uint
	FreePublicMemory   uint
	TotalPrivateMemory uint
	FreePrivateMemory  uint
	HardwareVersion    Version
	FirmwareVersion    Version
	TimeUTC            string
}
