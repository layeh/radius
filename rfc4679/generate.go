//go:generate go run ../cmd/radius-dict-gen/main.go -package rfc4679 -ignore ADSL-Forum-DHCP-Vendor-Specific -ignore ADSL-Forum-Device-Manufacturer-OUI -ignore ADSL-Forum-Device-Serial-Number -ignore ADSL-Forum-Device-Product-Class -ignore ADSL-Forum-Gateway-Manufacturer-OUI -output generated.go dictionary.rfc4679

package rfc4679
