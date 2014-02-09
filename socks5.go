package ladder

import (
	"io"
	"log"
	"net"
)

const SocksVersion = 5

var (
	SocksAuthNotRequired         = []byte{SocksVersion, 0}
	SocksAuthUserPasswd          = []byte{SocksVersion, 2}
	SocksAuthMethodNotMatch      = []byte{SocksVersion, 0xFF}
	SocksReplySuccess            = []byte{SocksVersion, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyServerFail         = []byte{SocksVersion, 1, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyNotAllowed         = []byte{SocksVersion, 2, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyNetworkUnreachable = []byte{SocksVersion, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyHostUnreachable    = []byte{SocksVersion, 4, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyRefused            = []byte{SocksVersion, 5, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyTTLExpired         = []byte{SocksVersion, 6, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyInvalidCommand     = []byte{SocksVersion, 7, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyInvalidAddrType    = []byte{SocksVersion, 8, 0, 1, 0, 0, 0, 0, 0, 0}
)

type Socks5Handler struct {
	client       net.Conn
	remote       TunnelSock
	user, passwd string
	should_auth  bool
}

func NewSocks5Handler(cli net.Conn, user, passwd string) *Socks5Handler {
	var auth bool = false
	if len(user) > 0 && len(passwd) > 0 {
		auth = true
	}
	return &Socks5Handler{cli, nil, user, passwd, auth}
}

func (s *Socks5Handler) Start(tun Tunnel) {
	if s.Authenticate() && s.HandleRequest(tun) {
		rst := s.CopyData()
		log.Printf("%s: %d/%d\n", s.remote.RemoteAddr(), rst.Up, rst.Down)
	}
	s.client.Close()
}

func (s *Socks5Handler) Authenticate() bool {
	/*
		+----+----------+----------+
		|VER | NMETHODS | METHODS  |
		+----+----------+----------+
		| 1  |    1     | 1 to 255 |
		+----+----------+----------+
	*/
	var buf [257]byte
	if _, err := io.ReadFull(s.client, buf[:2]); err != nil {
		return false
	} else if buf[0] != 5 {
		return false
	} else if buf[1] > 0 {
		if _, err := io.ReadFull(s.client, buf[2:2+buf[1]]); err != nil {
			return false
		}
	}

	/*
	   +----+--------+
	   |VER | METHOD |
	   +----+--------+
	   | 1  |   1    |
	   +----+--------+
	*/
	if s.should_auth {
		if buf[1] == 0 {
			s.client.Write(SocksAuthMethodNotMatch)
			return false
		}
		if _, err := s.client.Write(SocksAuthUserPasswd); err != nil {
			return false
		}
		return s.CheckUserPasswd()
	} else if _, err := s.client.Write(SocksAuthNotRequired); err != nil {
		return false
	}
	return true
}

func (s *Socks5Handler) CheckUserPasswd() bool {
	//TODO: protocol
	return false
}

func (s *Socks5Handler) HandleRequest(tun Tunnel) bool {
	/*Request:
	  +----+-----+-------+------+----------+----------+
	  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	  +----+-----+-------+------+----------+----------+
	  | 1  |  1  | X'00' |  1   | Variable |    2     |
	  +----+-----+-------+------+----------+----------+
	*/
	var buf [262]byte
	if _, err := io.ReadFull(s.client, buf[:4]); err != nil {
		return false
	} else if buf[0] != 5 {
		return false
	} else if buf[1] != 1 {
		s.client.Write(SocksReplyInvalidCommand)
		return false
	}

	var port uint16
	switch buf[3] {
	case 1:
		if _, err := io.ReadFull(s.client, buf[4:10]); err != nil {
			return false
		}
		port = uint16(buf[8])*256 + uint16(buf[9])
		s.remote = tun.NewSock(SocksAddrTypeIPv4, buf[4:8], port)
	case 3:
		if _, err := io.ReadFull(s.client, buf[4:5]); err != nil {
			return false
		} else if buf[4] == 0 {
			s.client.Write(SocksReplyHostUnreachable)
			return false
		} else if _, err = io.ReadFull(s.client, buf[5:7+buf[4]]); err != nil {
			return false
		}
		port = uint16(buf[5+buf[4]])*256 + uint16(buf[6+buf[4]])
		s.remote = tun.NewSock(SocksAddrTypeDomain, buf[5:5+buf[4]], port)
	case 4:
		if _, err := io.ReadFull(s.client, buf[4:22]); err != nil {
			return false
		}
		port = uint16(buf[20])*256 + uint16(buf[21])
		s.remote = tun.NewSock(SocksAddrTypeIPv6, buf[4:20], port)
	default:
		s.client.Write(SocksReplyInvalidAddrType)
		return false
	}

	/*
	   +----+-----+-------+------+----------+----------+
	   |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	   +----+-----+-------+------+----------+----------+
	   | 1  |  1  | X'00' |  1   | Variable |    2     |
	   +----+-----+-------+------+----------+----------+
	*/
	if s.remote != nil {
		s.client.Write(SocksReplySuccess)
		return true
	} else {
		s.client.Write(SocksReplyServerFail)
		return false
	}
}

type IOCopyStat struct {
	to_remote bool
	written   int64
	err       error
}

type Socks5ProxyResult struct {
	Up   int64
	Down int64
}

func copy_helper(ch chan IOCopyStat, dst io.Writer, src io.Reader, to_remote bool) {
	n, err := io.Copy(dst, src)
	ch <- IOCopyStat{to_remote, n, err}
}

func (s *Socks5Handler) CopyData() (rst Socks5ProxyResult) {
	ch := make(chan IOCopyStat, 2)
	go copy_helper(ch, s.remote, s.client, true)
	go copy_helper(ch, s.client, s.remote, false)

	remote_closed := false
	for i := 0; i < 2; i++ {
		copy_stat := <-ch
		if !remote_closed {
			s.remote.Close()
			remote_closed = true
		}
		if copy_stat.to_remote {
			rst.Up = copy_stat.written
		} else {
			rst.Down = copy_stat.written
		}
	}

	return rst
}
