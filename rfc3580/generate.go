//go:generate go run ../cmd/radius-dict-gen/main.go -package rfc3580 -output generated.go -ref Acct-Terminate-Cause:layeh.com/radius/rfc2866 -ref NAS-Port-Type:layeh.com/radius/rfc2865 -ref Tunnel-Type:layeh.com/radius/rfc2868 dictionary.rfc3580

package rfc3580
