package radius_test

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"layeh.com/radius"
	. "layeh.com/radius/rfc2865"
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

	server := radius.PacketServer{
		SecretSource: radius.StaticSecretSource(secret),
		Handler: radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
			username := UserName_GetString(r.Packet)
			if username == "tim" {
				w.Write(r.Response(radius.CodeAccessAccept))
			} else {
				w.Write(r.Response(radius.CodeAccessReject))
			}
		}),
	}

	var clientErr error
	go func() {
		defer server.Shutdown(context.Background())

		packet := radius.New(radius.CodeAccessRequest, secret)
		UserName_SetString(packet, "tim")
		client := radius.Client{
			Retry: time.Millisecond * 50,
		}
		response, err := client.Exchange(context.Background(), packet, pc.LocalAddr().String())
		if err != nil {
			clientErr = err
			return
		}
		if response.Code != radius.CodeAccessAccept {
			clientErr = fmt.Errorf("expected CodeAccessAccept, got %s\n", response.Code)
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

	var server *radius.TestServer
	handler := radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
		close(handlerCalled)
		atomic.AddInt32(&handlerState, 1)
		<-r.Context().Done()
		atomic.AddInt32(&handlerState, 1)
		time.Sleep(time.Millisecond * 15)
		atomic.AddInt32(&handlerState, 1)
	})
	server = radius.NewTestServer(handler, radius.StaticSecretSource(secret))
	defer server.Close()

	req := radius.New(radius.CodeAccessRequest, secret)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		client := radius.Client{
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
