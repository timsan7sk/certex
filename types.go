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
	"fmt"
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

// The primary object type. Such as a certificate, public key, or
// private key.
type Class int

// Set of classes supported by this package.
const (
	ClassData             Class = 0x00000000
	ClassCertificate      Class = 0x00000001
	ClassPublicKey        Class = 0x00000002
	ClassPrivateKey       Class = 0x00000003
	ClassSecretKey        Class = 0x00000004
	ClassDomainParameters Class = 0x00000006
)

var classString = map[Class]string{
	ClassData:             "CKO_DATA",
	ClassCertificate:      "CKO_CERTIFICATE",
	ClassPublicKey:        "CKO_PUBLIC_KEY",
	ClassPrivateKey:       "CKO_PRIVATE_KEY",
	ClassSecretKey:        "CKO_SECRET_KEY",
	ClassDomainParameters: "CKO_DOMAIN_PARAMETERS",
}

// Returns a human readable version of the object class.
func (c Class) String() string {
	if s, ok := classString[c]; ok {
		return s
	}
	return fmt.Sprintf("Class(0x%08x)", int(c))
}

func (c Class) ckType() (C.CK_OBJECT_CLASS, bool) {
	switch c {
	case ClassData:
		return C.CKO_DATA, true
	case ClassCertificate:
		return C.CKO_CERTIFICATE, true
	case ClassPublicKey:
		return C.CKO_PUBLIC_KEY, true
	case ClassPrivateKey:
		return C.CKO_PRIVATE_KEY, true
	case ClassSecretKey:
		return C.CKO_SECRET_KEY, true
	case ClassDomainParameters:
		return C.CKO_DOMAIN_PARAMETERS, true
	}
	return 0, false
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
	fl C.CK_FUNCTION_LIST_PTR
	h  C.CK_SESSION_HANDLE
	o  C.CK_OBJECT_HANDLE
	c  C.CK_OBJECT_CLASS
}

// ObjectHandle is a token-specific identifier for an object.
type ObjectHandle uint

// Returns the type of the object stored. For example, certificate, public
// key, or private key.
func (o Object) Class() Class {
	return Class(int(o.c))
}

// Represents a session to a slot.
//
// A session holds a listable set of objects, such as certificates and
// cryptographic keys.
type Slot struct {
	fl C.CK_FUNCTION_LIST_PTR
	h  C.CK_SESSION_HANDLE
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
	Label  string
	Model  string
	Serial string

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
