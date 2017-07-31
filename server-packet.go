package radius

import (
	"errors"
	"net"
	"sync"
)

type packetResponseWriter struct {
	// listener that received the packet
	conn net.PacketConn
	addr net.Addr
}

func (r *packetResponseWriter) Write(packet *Packet) error {
	raw, err := packet.Encode()
	if err != nil {
		return err
	}
	if _, err := r.conn.WriteTo(raw, r.addr); err != nil {
		return err
	}
	return nil
}

// PacketServer listens for RADIUS requests on a packet-based protocols (e.g.
// UDP).
type PacketServer struct {
	// The address on which the server listens. Defaults to :1812.
	Addr string
	// The network on which the server listens. Defaults to udp.
	Network      string
	SecretSource SecretSource
	Handler      Handler

	// Skip incoming packet authenticity validation.
	// This should only be set to true for debugging purposes.
	InsecureSkipVerify bool
}

// TODO: logger on PacketServer

// Serve accepts incoming connections on conn.
func (s *PacketServer) Serve(conn net.PacketConn) error {
	if s.Handler == nil {
		return errors.New("radius: nil Handler")
	}
	if s.SecretSource == nil {
		return errors.New("radius: nil SecretSource")
	}

	type activeKey struct {
		IP         string
		Identifier byte
	}

	var (
		activeLock sync.Mutex
		active     = map[activeKey]struct{}{}
	)

	for {
		var buff [MaxPacketLength]byte
		n, remoteAddr, err := conn.ReadFrom(buff[:])
		if err != nil {
			println(err.Error())
			if err.(*net.OpError).Temporary() { // TODO: ???
				return err
			}
			continue
		}

		secret, err := s.SecretSource.RADIUSSecret(remoteAddr)
		if err != nil {
			// TODO: log?
			continue
		}
		if len(secret) == 0 {
			continue
		}

		if !s.InsecureSkipVerify && !IsAuthenticRequest(buff[:n], secret) {
			// TODO: log?
			continue
		}

		packet, err := Parse(buff[:n], secret)
		if err != nil {
			// TODO: error logger
			continue
		}

		go func(packet *Packet, remoteAddr net.Addr) {
			key := activeKey{
				IP:         remoteAddr.String(),
				Identifier: packet.Identifier,
			}
			activeLock.Lock()
			if _, ok := active[key]; ok {
				activeLock.Unlock()
				return
			}
			active[key] = struct{}{}
			activeLock.Unlock()

			response := packetResponseWriter{
				conn: conn,
				addr: remoteAddr,
			}

			defer func() {
				activeLock.Lock()
				delete(active, key)
				activeLock.Unlock()
			}()

			request := Request{
				LocalAddr:  conn.LocalAddr(),
				RemoteAddr: remoteAddr,
				Packet:     packet,
			}

			s.Handler.ServeRADIUS(&response, &request)
		}(packet, remoteAddr)
	}
}

// ListenAndServe starts a RADIUS server on the address given in s.
func (s *PacketServer) ListenAndServe() error {
	if s.Handler == nil {
		return errors.New("radius: nil Handler")
	}
	if s.SecretSource == nil {
		return errors.New("radius: nil SecretSource")
	}

	addrStr := ":1812"
	if s.Addr != "" {
		addrStr = s.Addr
	}

	network := "udp"
	if s.Network != "" {
		network = s.Network
	}

	pc, err := net.ListenPacket(network, addrStr)
	if err != nil {
		return err
	}
	defer pc.Close()
	return s.Serve(pc)
}

// TODO: UDPServer.Shutdown(context.Context) ?
