//go:generate go run ../cmd/radius-dict-gen/main.go -package rfc2869 -ignore ARAP-Password -ignore ARAP-Features -ignore EAP-Message -ignore ARAP-Challenge-Response -output generated.go /usr/share/freeradius/dictionary.rfc2869

package rfc2869
