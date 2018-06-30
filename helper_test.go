package radius

import "net"

type TestServer struct {
	Addr string

	Server *PacketServer

	l        net.PacketConn
	serveErr error
}

func NewTestServer(handler Handler, secretSource SecretSource) *TestServer {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}

	s := &TestServer{
		Addr: conn.LocalAddr().String(),
		Server: &PacketServer{
			Handler:      handler,
			SecretSource: secretSource,
		},
		l: conn,
	}

	go func() {
		s.serveErr = s.Server.Serve(s.l)
	}()

	return s
}

func (s *TestServer) Close() error {
	return s.l.Close()
}
