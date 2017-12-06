package dictionary

import "strconv"

type Dictionary struct {
	Attributes []*Attribute
	Values     []*Value
	Vendors    []*Vendor
}

func (d *Dictionary) AttributeByName(name string) *Attribute {
	for _, attr := range d.Attributes {
		if attr.Name == name {
			return attr
		}
	}
	return nil
}

func (d *Dictionary) VendorByName(name string) *Vendor {
	for _, vendor := range d.Vendors {
		if vendor.Name == name {
			return vendor
		}
	}
	return nil
}

func (d *Dictionary) vendorByNameOrNumber(name string, number int) *Vendor {
	for _, vendor := range d.Vendors {
		if vendor.Name == name || vendor.Number == number {
			return vendor
		}
	}
	return nil
}

type AttributeType int

const (
	AttributeString AttributeType = iota + 1
	AttributeOctets
	AttributeIPAddr
	AttributeDate
	AttributeInteger
	AttributeIPv6Addr
	AttributeIPv6Prefix
	AttributeIFID
	AttributeInteger64

	AttributeVSA
	// TODO: non-standard types?
)

func (t AttributeType) String() string {
	switch t {
	case AttributeString:
		return "string"
	case AttributeOctets:
		return "octets"
	case AttributeIPAddr:
		return "ipaddr"
	case AttributeDate:
		return "date"
	case AttributeInteger:
		return "integer"
	case AttributeIPv6Addr:
		return "ipv6addr"
	case AttributeIPv6Prefix:
		return "ipv6prefix"
	case AttributeIFID:
		return "ifid"
	case AttributeInteger64:
		return "integer64"
	case AttributeVSA:
		return "vsa"
	}
	return "AttributeType(" + strconv.Itoa(int(t)) + ")"
}

type Attribute struct {
	Name string
	OID  string
	Type AttributeType

	FlagEncrypt *int
	FlagHasTag  *bool
}

type Value struct {
	Attribute string
	Name      string
	Number    int
}

type Vendor struct {
	Name   string
	Number int

	TypeOctets   int
	LengthOctets int

	Attributes []*Attribute
	Values     []*Value
}

func (v *Vendor) AttributeByName(name string) *Attribute {
	for _, attr := range v.Attributes {
		if attr.Name == name {
			return attr
		}
	}
	return nil
}
