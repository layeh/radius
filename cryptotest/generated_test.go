package cryptotest

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"layeh.com/radius"
)

type TestServer struct {
	Addr     string
	Server   *radius.PacketServer
	l        net.PacketConn
	serveErr error
}

func NewTestServer(handler radius.Handler, secretSource radius.SecretSource) *TestServer {
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
		Server: &radius.PacketServer{
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

func TestCOASaltEncryptionFromClientToServer(t *testing.T) {
	secret := []byte(`12345`)
	expected := []byte("testsecret")

	handler := radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
		resp := r.Response(radius.CodeCoAACK)

		returned, err := CTOctects_Lookup(r.Packet)
		if err != nil {
			t.Fatalf("Could not decode encrypted tunnel password with error %v", err)
		}
		if !bytes.Equal(returned, expected) {
			t.Fatalf("incorrect tunnel password: expected %v, got %v", expected, returned)
		}
		if err := w.Write(resp); err != nil {
			t.Fatal(err)
		}
	})

	server := NewTestServer(handler, radius.StaticSecretSource(secret))
	defer server.Close()

	client := radius.Client{
		Retry:           50 * time.Millisecond,
		MaxPacketErrors: 2,
	}

	req := radius.New(radius.CodeCoARequest, secret)
	if err := CTOctects_Add(req, expected); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.Exchange(ctx, req, server.Addr)
	if err != nil {
		t.Fatalf("Exchange error %v", err)
	}
}

func newRadiusPacket() *radius.Packet {
	p := &radius.Packet{
		Attributes:    radius.Attributes{},
		Authenticator: [16]byte{0x0B, 0x00, 0x00, 0x07, 0x0B, 0x00, 0x00, 0x07, 0x0B, 0x00, 0x00, 0x07, 0x0B, 0x00, 0x00, 0x07},
		Secret:        []byte{0x0B, 0x00, 0x00, 0x07},
	}
	p.CryptoAuthenticator = p.Authenticator
	return p
}

func Test_CTIPADDR_Add(t *testing.T) {
	tunnelCTIPADDRAdd := func() (p *radius.Packet) {
		p = newRadiusPacket()
		testIP := net.IPv4(8, 8, 8, 8)
		if err := CTIPADDR_Add(p, testIP); err != nil {
			t.Fatalf("DTA4LIMedIPAddress_Set unexpected err %s", err)
		}

		returned, err := CTIPADDR_Lookup(p)
		if err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if !returned.Equal(testIP) {
			t.Fatalf("decrypted DTA4LIMedIPAddress does not match encrypted")
		}

		returnedArray, err := CTIPADDR_Gets(p)
		if err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if len(returnedArray) != 1 || !testIP.Equal(returnedArray[0]) {
			t.Fatalf("decrypted DTA4LIMedIPAddress does not match encrypted")
		}

		return
	}

	p1 := tunnelCTIPADDRAdd()
	p2 := tunnelCTIPADDRAdd()

	if bytes.Equal(p1.Attributes[0].Attribute, p2.Attributes[0].Attribute) {
		t.Fatalf("tunnel encrypted passwords should not be identical since salts are rands")
	}
}

func Test_WrongDecryptAuthenticator(t *testing.T) {
	packet := newRadiusPacket()

	var testInt CTInt = 1
	err := CTInt_Add(packet, 1)
	if err != nil {
		t.Fatalf("unexpected err: %s", err)
	}

	returned, err := CTInt_Lookup(packet)
	if err != nil {
		t.Fatalf("unexpected err: %s", err)
	}

	if returned != testInt {
		t.Fatalf("returned int does not match encrypted")
	}

	packet.CryptoAuthenticator[3] = 0xff
	_, err = CTInt_Lookup(packet)

	if err == nil {
		t.Fatalf("expected a decoder failure")
	}
}
