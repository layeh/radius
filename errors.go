package radius

// NonAuthenticResponseError is returned when a client was expecting
// a valid response but did not receive one.
type NonAuthenticResponseError struct {
}

func (e *NonAuthenticResponseError) Error() string {
	return `radius: non-authentic response`
}

// MalformedRequestError is returned by Client.Exchange when the request packet
// could not be encoded into its wire format. It indicates a problem with the
// request itself (for example, attributes that are too long or an unknown
// packet Code), so retrying the same request against another server will not
// help.
//
// Callers can use errors.As to distinguish this client-side error from network
// errors (which implement net.Error) when deciding whether to fail over to
// another server:
//
//	resp, err := client.Exchange(ctx, packet, addr)
//	var malformed *radius.MalformedRequestError
//	switch {
//	case err == nil:
//		// success
//	case errors.As(err, &malformed):
//		// the request is invalid; do not retry against other servers
//	default:
//		// network or server error; failover to the next server may help
//	}
type MalformedRequestError struct {
	Err error
}

func (e *MalformedRequestError) Error() string {
	return "radius: malformed request: " + e.Err.Error()
}

func (e *MalformedRequestError) Unwrap() error {
	return e.Err
}
