package radius

import (
	"errors"
	"net"
	"sync"
)

// Handler is a value that can handle a server's RADIUS packet event.
type Handler interface {
	ServeRadius(w ResponseWriter, p *Packet)
}

// HandlerFunc is a wrapper that allows ordinary functions to be used as a
// handler.
type HandlerFunc func(w ResponseWriter, p *Packet)

// ServeRadius calls h(w, p).
func (h HandlerFunc) ServeRadius(w ResponseWriter, p *Packet) {
	h(w, p)
}

// ResponseWriter is used by Handler when replying to a RADIUS packet.
type ResponseWriter interface {
	// LocalAddr returns the address of the local server that accepted the
	// packet.
	LocalAddr() net.Addr
	// RemoteAddr returns the address of the remote client that sent to packet.
	RemoteAddr() net.Addr

	// Write sends a packet to the sender.
	Write(packet *Packet) error

	// AccessAccept sends an Access-Accept packet to the sender that includes
	// the given attributes.
	AccessAccept(attributes ...*Attribute) error
	// AccessAccept sends an Access-Reject packet to the sender that includes
	// the given attributes.
	AccessReject(attributes ...*Attribute) error
	// AccessAccept sends an Access-Challenge packet to the sender that includes
	// the given attributes.
	AccessChallenge(attributes ...*Attribute) error
}

type responseWriter struct {
	// listener that received the packet
	conn *net.UDPConn
	// where the packet came from
	addr *net.UDPAddr
	// original packet
	packet *Packet
}

func (r *responseWriter) LocalAddr() net.Addr {
	return r.conn.LocalAddr()
}

func (r *responseWriter) RemoteAddr() net.Addr {
	return r.addr
}

func (r *responseWriter) accessRespond(code Code, attributes ...*Attribute) error {
	packet := Packet{
		Code:          code,
		Identifier:    r.packet.Identifier,
		Authenticator: r.packet.Authenticator,

		Secret: r.packet.Secret,

		Dictionary: r.packet.Dictionary,

		Attributes: attributes,
	}
	return r.Write(&packet)
}

func (r *responseWriter) AccessAccept(attributes ...*Attribute) error {
	// TOOD: do not send if packet was not Access-Request
	return r.accessRespond(CodeAccessAccept, attributes...)
}

func (r *responseWriter) AccessReject(attributes ...*Attribute) error {
	// TOOD: do not send if packet was not Access-Request
	return r.accessRespond(CodeAccessReject, attributes...)
}

func (r *responseWriter) AccessChallenge(attributes ...*Attribute) error {
	// TOOD: do not send if packet was not Access-Request
	return r.accessRespond(CodeAccessChallenge, attributes...)
}

func (r *responseWriter) Write(packet *Packet) error {
	raw, err := packet.Encode()
	if err != nil {
		return err
	}
	if _, err := r.conn.WriteToUDP(raw, r.addr); err != nil {
		return err
	}
	return nil
}

// Server is a server that listens for and handles RADIUS packets.
type Server struct {
	// Address to bind the server on. If empty, the address defaults to ":1812".
	Addr string
	// Network of the server. Valid values are "udp", "udp4", "udp6". If empty,
	// the network defaults to "udp".
	Network string
	// The shared secret between the client and server.
	Secret []byte

	// TODO: allow a secret function to be defined, which returned the secret
	// that should be used for the given client.

	// Dictionary used when decoding incoming packets.
	Dictionary *Dictionary

	// The packet handler that handles incoming, valid packets.
	Handler Handler

	listener *net.UDPConn
}

// ListenAndServe starts a RADIUS server on the address given in s.
func (s *Server) ListenAndServe() error {
	if s.listener != nil {
		return errors.New("radius: server already started")
	}

	if s.Handler == nil {
		return errors.New("radius: nil Handler")
	}

	addrStr := ":1812"
	if s.Addr != "" {
		addrStr = s.Addr
	}

	network := "udp"
	if s.Network != "" {
		network = s.Network
	}

	addr, err := net.ResolveUDPAddr(network, addrStr)
	if err != nil {
		return err
	}
	s.listener, err = net.ListenUDP(network, addr)
	if err != nil {
		return err
	}

	type activeKey struct {
		IP         string
		Identifier byte
	}

	var (
		activeLock sync.Mutex
		active     = map[activeKey]bool{}
	)

	for {
		buff := make([]byte, 4096)
		n, remoteAddr, err := s.listener.ReadFromUDP(buff)
		if err != nil && !err.(*net.OpError).Temporary() {
			break
		}
		if n == 0 {
			continue
		}
		buff = buff[:n]
		//go s.handleUDP(s.listener, buff, remoteAddr)
		go func(conn *net.UDPConn, buff []byte, remoteAddr *net.UDPAddr) {
			packet, err := Parse(buff, s.Secret, s.Dictionary)
			if err != nil {
				return
			}
			key := activeKey{
				IP:         remoteAddr.String(),
				Identifier: packet.Identifier,
			}
			activeLock.Lock()
			if _, ok := active[key]; ok {
				activeLock.Unlock()
				return
			}
			active[key] = true
			activeLock.Unlock()

			response := responseWriter{
				conn:   conn,
				addr:   remoteAddr,
				packet: packet,
			}

			s.Handler.ServeRadius(&response, packet)

			activeLock.Lock()
			delete(active, key)
			activeLock.Unlock()
		}(s.listener, buff, remoteAddr)
	}
	// TODO: only return nil if s.Close was called
	s.listener = nil
	return nil
}

// Close stops listening for packets. Any packet that is currently being
// handled will not be able to respond to the sender.
func (s *Server) Close() error {
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}
