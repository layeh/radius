//go:generate go run cmd/radius-dict-gen/main.go -package rfc2865 -output rfc2865/generated.go /usr/share/freeradius/dictionary.rfc2865
//go:generate go run cmd/radius-dict-gen/main.go -package rfc2866 -output rfc2866/generated.go /usr/share/freeradius/dictionary.rfc2866
//go:generate go run cmd/radius-dict-gen/main.go -package rfc2867 -output rfc2867/generated.go -ref Acct-Status-Type:layeh.com/radius/rfc2866 /usr/share/freeradius/dictionary.rfc2867
//go:generate go run cmd/radius-dict-gen/main.go -package rfc2869 -ignore Event-Timestamp -ignore ARAP-Password -ignore ARAP-Features -ignore EAP-Message -ignore ARAP-Challenge-Response -output rfc2869/generated.go /usr/share/freeradius/dictionary.rfc2869
//go:generate go run cmd/radius-dict-gen/main.go -package rfc3576 -output rfc3576/generated.go -ref Service-Type:layeh.com/radius/rfc2865 /usr/share/freeradius/dictionary.rfc3576
//go:generate go run cmd/radius-dict-gen/main.go -package rfc5176 -output rfc5176/generated.go -ref Error-Cause:layeh.com/radius/rfc3576 /usr/share/freeradius/dictionary.rfc5176

package radius
