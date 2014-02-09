package main

import (
	"flag"
	"github.com/lodevil/ladder"
	"log"
	"net"
	"os"
	"runtime/pprof"
	"strconv"
)

type Tunnel struct{}

func (t *Tunnel) NewSock(addr_type int, addr []byte, port uint16) ladder.TunnelSock {
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
		return nil
	} else {
		return conn
	}
}

func (t *Tunnel) Init(cfg ladder.Config) error {
	return nil
}

func (t *Tunnel) Shutdown() error {
	return nil
}

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

func main() {
	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	p := &Tunnel{}
	auth := ladder.NewSimpleAuth()
	auth["lo"] = "1234"

	li, _ := net.Listen("tcp", "127.0.0.1:8989")
	for {
		cli, _ := li.Accept()
		go ladder.HandleSocks5(cli, p, auth)
	}
}
