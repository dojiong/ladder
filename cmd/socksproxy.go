package main

import (
	"github.com/lodevil/ladder"
	"log"
	"net"
	"strconv"
)

type Pipe struct{}

func (p *Pipe) New(addr_type int, addr []byte, port uint16) ladder.SockLine {
	var host string
	switch addr_type {
	case ladder.SocksAddrTypeIPv6:
		return nil
	case ladder.SocksAddrTypeIPv4:
		host = net.IP(addr).String()
	case ladder.SocksAddrTypeDomain:
		host = string(addr)
	}
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	if conn, err := net.Dial("tcp", host); err != nil {
		log.Println("connect fail", host, err)
		return nil
	} else {
		log.Println("got", host)
		return conn
	}
}

func main() {
	p := &Pipe{}

	li, _ := net.Listen("tcp", "127.0.0.1:8989")
	for {
		cli, _ := li.Accept()
		h := ladder.NewSocks5Handler(cli, "", "")
		go h.Start(p)
	}
}
