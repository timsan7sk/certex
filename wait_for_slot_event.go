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

CK_RV wait_for_slot_event(CK_FUNCTION_LIST_PTR fl, CK_FLAGS flags, CK_ULONG_PTR slot){
	return (*fl->C_WaitForSlotEvent)(flags, (CK_SLOT_ID_PTR) slot, NULL);
}
*/
import "C"
import "fmt"

func (m *Cryptoki) WaitForSlotEvent(flags uint) chan SlotEvent {
	seChan := make(chan SlotEvent, 1)
	go m.waitForSlotEventHelper(flags, seChan)
	return seChan
}
func (m *Cryptoki) waitForSlotEventHelper(flags uint, seChan chan SlotEvent) {
	var slotID C.CK_ULONG
	if rv := C.wait_for_slot_event(m.fl, C.CK_FLAGS(flags), &slotID); rv != C.CKR_OK {
		fmt.Printf("waitForSlotEventHelper: 0x%08x\n", rv)
	}
	seChan <- SlotEvent{uint(slotID)}
	close(seChan)
}
