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
import "fmt"

func (m *Cryptoki) Slot(id uint, opts Options) (*Slot, error) {

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
		s.CloseSession()
		return nil, err
	}
	return s, nil
}
