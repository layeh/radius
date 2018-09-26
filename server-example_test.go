package radius_test

import (
	"log"

	"layeh.com/radius"
	. "layeh.com/radius/rfc2865"
)

var (
	Username = "tim"
	Password = "12345"
)

func Example_packetServer() {
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		username := UserName_GetString(r.Packet)
		password := UserPassword_GetString(r.Packet)

		var code radius.Code
		if username == Username && password == Password {
			code = radius.CodeAccessAccept
		} else {
			code = radius.CodeAccessReject
		}
		log.Printf("Writing %v to %v", code, r.RemoteAddr)
		w.Write(r.Response(code))
	}

	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(`secret`)),
	}

	log.Printf("Starting server on :1812")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
