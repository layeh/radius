package radius

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestClient_Exchange_expired(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, r *Request) {
		// ignore
	})
	server := newTestServer(handler, StaticSecretSource([]byte(`12345`)))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), -time.Hour)
	defer cancel()

	req := New(CodeAccessRequest, []byte(`secret`))

	client := Client{}
	resp, err := client.Exchange(ctx, req, server.Addr)
	if resp != nil {
		t.Fatalf("got non-nil response (%v); expected nil", resp)
	}
	if err == nil {
		t.Fatal("got nil error; expected one")
	}
	if netErr, ok := err.(net.Error); !ok {
		t.Fatal("err is not a net.Error")
	} else if !netErr.Timeout() {
		t.Fatal("got netErr.Timeout() = false; expected true")
	}
}
