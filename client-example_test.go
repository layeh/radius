package radius_test

import (
	"context"
	"log"

	"layeh.com/radius"
	. "layeh.com/radius/rfc2865"
)

var (
	ClientUsername = "tim"
	ClientPassword = "12345"
)

func Example_client() {
	packet := radius.New(radius.CodeAccessRequest, []byte(`secret`))
	UserName_SetString(packet, ClientUsername)
	UserPassword_SetString(packet, ClientPassword)
	response, err := radius.Exchange(context.Background(), packet, "localhost:1812")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Code:", response.Code)
}
