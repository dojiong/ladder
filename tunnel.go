package ladder

import (
	"net"
)

const (
	SocksAddrTypeIPv4 = iota
	SocksAddrTypeIPv6
	SocksAddrTypeDomain
)

type Tunnel interface {
	Init(cfg Config) error
	Shutdown() error
	NewSock(addr_type int, addr []byte, port uint16) TunnelSock
}

type TunnelSock interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	RemoteAddr() net.Addr
}
