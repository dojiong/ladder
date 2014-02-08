package ladder

const ()

type PipeConfig struct {
}

const (
	SocksAddrTypeIPv4 = iota
	SocksAddrTypeIPv6
	SocksAddrTypeDomain
)

type SockPipe interface {
	New(addr_type int, addr []byte, port uint16) SockLine
}

type SockLine interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
}
