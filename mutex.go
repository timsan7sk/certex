package certex

// Locking Mutex variable
func (m *Cryptoki) Lock() {
	m.mu.Lock()
}

// Try to locking Mutex variable
func (m *Cryptoki) TryLock() bool {
	return m.mu.TryLock()
}

// Unlocking Mutex variable
func (m *Cryptoki) Unlock() {
	m.mu.Unlock()
}
