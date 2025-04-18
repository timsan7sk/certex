package certex

type Certex interface {
	CreateSlot(id uint32, opts SlotOptions) error
	Lock()
	TryLock() bool
	Unlock()
	Slot(id uint32, opts Options) (*Slot, error)
	Close() error
}

var _ Certex = (*Cryptoki)(nil)
