package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

var secret = flag.String("secret", "", "shared RADIUS secret between clients and server")
var command string
var arguments []string

func handler(w radius.ResponseWriter, r *radius.Request) {
	username, err1 := rfc2865.UserName_LookupString(r.Packet)
	password, err2 := rfc2865.UserPassword_LookupString(r.Packet)
	if err1 != nil || err2 != nil {
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}
	log.Printf("%s requesting access (%s #%d)\n", username, r.RemoteAddr, r.Identifier)

	cmd := exec.Command(command, arguments...)

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "RADIUS_USERNAME="+username, "RADIUS_PASSWORD="+password)

	output, err := cmd.Output()
	if err != nil {
		log.Printf("handler error: %s\n", err)
	}

	var code radius.Code
	if cmd.ProcessState != nil && cmd.ProcessState.Success() {
		code = radius.CodeAccessAccept
		log.Printf("%s accepted (%s #%d)\n", username, r.RemoteAddr, r.Identifier)
	} else {
		code = radius.CodeAccessReject
		log.Printf("%s rejected (%s #%d)\n", username, r.RemoteAddr, r.Identifier)
	}
	resp := r.Response(code)

	if len(output) > 0 {
		rfc2865.ReplyMessage_Set(r.Packet, output)
	}

	w.Write(resp)
}

const usage = `
program is executed when an Access-Request RADIUS packet is received. If
program exits sucessfully, an Access-Accept response is sent, otherwise, an
Access-Reject is sent. If standard out is non-empty, it is included as an
Reply-Message attribute in the response.

The environment variables RADIUS_USERNAME and RADIUS_PASSWORD are set which hold
the username and password, respectively.
`

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <program> [program arguments...]\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, usage)
	}
	flag.Parse()

	if *secret == "" || flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	command = flag.Arg(0)
	arguments = flag.Args()[1:]

	log.Println("radserver starting")

	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(*secret)),
		ErrLog:       log.New(os.Stderr, "", log.Ltime|log.Lshortfile|log.Ldate),
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
