package dns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type Server struct {
	udp *dns.Server
	tcp *dns.Server
}

// ":53" needs cap_net_bind_service or root
func Listen(addr string, h dns.Handler) (*Server, error) {
	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dns: listen udp %s: %w", addr, err)
	}
	// resolve tcp to the same port udp bound, in case addr used ":0"
	tcpAddr := udpConn.LocalAddr().String()
	tcpLn, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("dns: listen tcp %s: %w", tcpAddr, err)
	}

	s := &Server{
		udp: &dns.Server{PacketConn: udpConn, Handler: h},
		tcp: &dns.Server{Listener: tcpLn, Handler: h},
	}
	return s, nil
}

// returns the first listener error; usually just the one shutdown causes by
// closing its socket, which miekg/dns doesnt report as a real error
func (s *Server) Serve() error {
	errc := make(chan error, 2)
	go func() { errc <- s.udp.ActivateAndServe() }()
	go func() { errc <- s.tcp.ActivateAndServe() }()
	if err := <-errc; err != nil {
		return err
	}
	return <-errc
}

func (s *Server) Addr() string {
	return s.udp.PacketConn.LocalAddr().String()
}

func (s *Server) Shutdown() error {
	err1 := s.udp.Shutdown()
	err2 := s.tcp.Shutdown()
	if err1 != nil {
		return err1
	}
	return err2
}
