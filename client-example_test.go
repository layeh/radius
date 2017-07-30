package radius_test

import (
	"context"
	"fmt"

	"layeh.com/radius"
	. "layeh.com/radius/rfc2865"
)

var (
	Username = "tim"
	Password = "12345"
)

func Example_client() {
	packet := radius.New(radius.CodeAccessRequest, []byte(`secret`))
	UserName_SetString(packet, Username)
	UserPassword_SetString(packet, Password)
	response, err := radius.Exchange(context.Background(), packet, "localhost:1812")
	if err != nil {
		panic(err)
	}

	if response.Code == radius.CodeAccessAccept {
		fmt.Println("Accepted")
	} else {
		fmt.Println("Denied")
	}
}
