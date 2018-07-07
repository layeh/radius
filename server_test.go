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

	if err := server.Serve(pc); err != nil {
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
