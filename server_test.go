package radius

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketServer_basic(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("123456790")
	const UserNameType = 1

	server := PacketServer{
		SecretSource: StaticSecretSource(secret),
		Handler: HandlerFunc(func(w ResponseWriter, r *Request) {
			username := String(r.Get(UserNameType))
			if username == "tim" {
				w.Write(r.Response(CodeAccessAccept))
			} else {
				w.Write(r.Response(CodeAccessReject))
			}
		}),
	}

	var clientErr error
	go func() {
		defer server.Shutdown(context.Background())

		packet := New(CodeAccessRequest, secret)
		username, _ := NewString("tim")
		packet.Set(UserNameType, username)
		client := Client{
			Retry: time.Millisecond * 50,
		}
		response, err := client.Exchange(context.Background(), packet, pc.LocalAddr().String())
		if err != nil {
			clientErr = err
			return
		}
		if response.Code != CodeAccessAccept {
			clientErr = fmt.Errorf("expected CodeAccessAccept, got %s", response.Code)
		}
	}()

	if err := server.Serve(pc); err != ErrServerShutdown {
		t.Fatal(err)
	}

	server.Shutdown(context.Background())

	if clientErr != nil {
		t.Fatal(err)
	}
}

func TestPacketServer_shutdown(t *testing.T) {
	secret := []byte(`12345`)

	var handlerState int32

	handlerCalled := make(chan struct{})

	var server *TestServer
	handler := HandlerFunc(func(w ResponseWriter, r *Request) {
		close(handlerCalled)
		atomic.AddInt32(&handlerState, 1)
		<-r.Context().Done()
		atomic.AddInt32(&handlerState, 1)
		time.Sleep(time.Millisecond * 15)
		atomic.AddInt32(&handlerState, 1)
	})
	server = NewTestServer(handler, StaticSecretSource(secret))
	defer server.Close()

	req := New(CodeAccessRequest, secret)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		client := Client{
			Retry:           time.Millisecond * 5,
			MaxPacketErrors: 2,
		}
		client.Exchange(ctx, req, server.Addr)
	}()

	<-handlerCalled
	if err := server.Server.Shutdown(context.Background()); err != nil {
		t.Fatalf("got ShutDown error %v; expecting nil", err)
	}
	if state := atomic.LoadInt32(&handlerState); state != 3 {
		t.Fatalf("handlerState = %d; expecting 3", state)
	}
}

func TestRequest_context(t *testing.T) {
	req := &Request{
		Packet: &Packet{},
	}
	if req.Context() != context.Background() {
		t.Fatalf("req.Context() = %v; expecting context.Background()", req.Context())
	}

	req2 := req.WithContext(context.Background())
	if req == req2 {
		t.Fatal("expected WithContext requests to differ")
	}
	if req.Packet != req2.Packet {
		t.Fatalf("expected WithContext request packets to be the same")
	}

	func() {
		defer func() {
			err := recover()
			if err == nil {
				t.Fatal("expected recover() to be non-nil")
			}
			errStr, ok := err.(string)
			if !ok || errStr != "nil ctx" {
				t.Fatalf("got recover() = %v; expected nil ctx", err)
			}
		}()
		req.WithContext(nil)
	}()
}

type dummyPacketConn struct{}

func (dummyPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) { panic("unimplemented") }
func (dummyPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error)  { panic("unimplemented") }
func (dummyPacketConn) Close() error                                        { panic("unimplemented") }
func (dummyPacketConn) LocalAddr() net.Addr                                 { panic("unimplemented") }
func (dummyPacketConn) SetDeadline(t time.Time) error                       { panic("unimplemented") }
func (dummyPacketConn) SetReadDeadline(t time.Time) error                   { panic("unimplemented") }
func (dummyPacketConn) SetWriteDeadline(t time.Time) error                  { panic("unimplemented") }

func TestPacketServer_singleUse(t *testing.T) {
	secret := []byte("12345")

	serverCtx, serverCtxCancel := context.WithCancel(context.Background())

	handlerReceived := make(chan struct{})
	server := NewTestServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		close(handlerReceived)
		<-serverCtx.Done()
	}), StaticSecretSource(secret))

	go func() {
		packet := New(CodeAccessRequest, secret)
		Exchange(serverCtx, packet, server.Addr)
	}()

	<-handlerReceived

	shutdownCtx, shutdownCtxCancel := context.WithTimeout(context.Background(), time.Millisecond*25)
	defer shutdownCtxCancel()
	err := server.Server.Shutdown(shutdownCtx)
	if err != context.DeadlineExceeded {
		t.Fatalf("got err %v; expecting context.DeadlineExceeded", err)
	}

	err = server.Server.Serve(dummyPacketConn{})
	if err != ErrServerShutdown {
		t.Fatalf("got err %v; expecting ErrServerShutdown", err)
	}

	serverCtxCancel()
	time.Sleep(time.Millisecond * 50) // racy otherwise

	err = server.Server.Serve(dummyPacketConn{})
	if err != ErrServerShutdown {
		t.Fatalf("got err %v; expecting ErrServerShutdown", err)
	}
}
