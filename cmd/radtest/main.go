package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const usage = `
Sends an Access-Request RADIUS packet to a server and prints the result.
`

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <user> <password> <radius-server>[:port] <nas-port-number> <secret>\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, usage)
	}
	timeout := flag.Duration("timeout", time.Second*10, "timeout for the request to finish")
	flag.Parse()
	if flag.NArg() != 5 {
		flag.Usage()
		os.Exit(1)
	}

	host, port, err := net.SplitHostPort(flag.Arg(2))
	if err != nil {
		host = flag.Arg(2)
		port = "1812"
	}
	hostport := net.JoinHostPort(host, port)

	packet := radius.New(radius.CodeAccessRequest, []byte(flag.Arg(4)))
	rfc2865.UserName_SetString(packet, flag.Arg(0))
	rfc2865.UserPassword_SetString(packet, flag.Arg(1))
	nasPort, _ := strconv.Atoi(flag.Arg(3))
	rfc2865.NASPort_Set(packet, rfc2865.NASPort(nasPort))

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	received, err := radius.Exchange(ctx, packet, hostport)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	status := received.Code.String()
	if msg, err := rfc2865.ReplyMessage_LookupString(received); err == nil {
		status += " (" + msg + ")"
	}

	fmt.Println(status)

	if received.Code != radius.CodeAccessAccept {
		os.Exit(2)
	}
}
