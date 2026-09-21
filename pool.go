package certex

import (
	"context"
	"fmt"
	"sync/atomic"
)

// SessionPool управляет пулом горячих сессий к аппаратному токену для конкурентной подписи.
type SessionPool struct {
	mod      *Cryptoki
	slotID   uint32
	opts     Options
	sessions chan *Slot
	closed   atomic.Bool
}

// NewSessionPool инициализирует заданное количество параллельных сессий.
func NewSessionPool(mod *Cryptoki, slotID uint32, opts Options, size int) (*SessionPool, error) {
	pool := &SessionPool{
		mod:      mod,
		slotID:   slotID,
		opts:     opts,
		sessions: make(chan *Slot, size),
	}

	for i := 0; i < size; i++ {
		slot, err := mod.Slot(slotID, opts)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("failed to provision pool session %d: %w", i, err)
		}
		pool.sessions <- slot
	}
	return pool, nil
}

// Acquire извлекает свободную сессию из пула. Блокирует выполнение до появления свободной.
func (p *SessionPool) Acquire(ctx context.Context) (*Slot, error) {
	if p.closed.Load() {
		return nil, fmt.Errorf("session pool is terminated")
	}
	select {
	case slot := <-p.sessions:
		return slot, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Release возвращает сессию в пул для повторного использования.
func (p *SessionPool) Release(slot *Slot) {
	if p.closed.Load() {
		slot.Close()
		return
	}
	p.sessions <- slot
}

// Close детерминированно завершает все активные сессии в пуле.
func (p *SessionPool) Close() {
	if p.closed.Swap(true) {
		return
	}
	close(p.sessions)
	for slot := range p.sessions {
		slot.Close()
	}
}