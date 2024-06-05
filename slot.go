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
import "C"
import (
	"fmt"
	"reflect"
)

func (m *Cryptoki) Slot(id uint32, opts Options) (*Slot, error) {

	if opts.AdminPIN != "" && opts.PIN != "" {
		return nil, fmt.Errorf("can't specify pin and admin pin")
	}

	hs, err := m.openSession(id, opts)
	if err != nil {
		return nil, err
	}

	s := &Slot{
		fl: m.fl,
		h:  hs,
		rw: opts.ReadWrite,
	}
	if err := s.login(opts.PIN, C.CKU_USER); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Configures a slot object. Internally this calls InitToken and
// InitPIN to set the admin and user PIN on the slot.
func (m *Cryptoki) CreateSlot(id uint32, opts SlotOptions) error {
	v := reflect.ValueOf(opts)
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).String() == "" {
			return fmt.Errorf("check options: %s not provided", t.Field(i).Name)
		}
	}
	var cLabel [32]C.CK_UTF8CHAR
	if !ckStringPadded(cLabel[:], opts.Label) {
		return fmt.Errorf("createSlot: label too long")
	}

	if err := m.InitToken(id, opts); err != nil {
		return err
	}

	so := Options{
		AdminPIN:  opts.AdminPIN,
		ReadWrite: true,
	}
	s, err := m.Slot(id, so)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.initPIN(opts.PIN); err != nil {
		return err
	}
	if err := s.logout(); err != nil {
		return err
	}
	return nil
}
