// dictionary.mikrotik: https://wiki.mikrotik.com/wiki/Manual:RADIUS_Client/vendor_dictionary

//go:generate go run ../../cmd/radius-dict-gen/main.go -package mikrotik -output generated.go dictionary.mikrotik

package mikrotik
