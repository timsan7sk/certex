package certex

type Certex interface {
	Close() error
}

var _ Certex = (*Cryptoki)(nil)
