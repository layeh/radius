package dictionary

func AttributeByName(attrs []*Attribute, name string) *Attribute {
	for _, attr := range attrs {
		if attr.Name == name {
			return attr
		}
	}
	return nil
}

func AttributeByOID(attrs []*Attribute, oid string) *Attribute {
	for _, attr := range attrs {
		if attr.OID == oid {
			return attr
		}
	}
	return nil
}

func ValuesByAttribute(values []*Value, attribute string) []*Value {
	var matched []*Value
	for _, value := range values {
		if value.Attribute == attribute {
			matched = append(matched, value)
		}
	}
	return matched
}

func VendorByName(vendors []*Vendor, name string) *Vendor {
	for _, vendor := range vendors {
		if vendor.Name == name {
			return vendor
		}
	}
	return nil
}

func VendorByNumber(vendors []*Vendor, number int) *Vendor {
	for _, vendor := range vendors {
		if vendor.Number == number {
			return vendor
		}
	}
	return nil
}

func vendorByNameOrNumber(vendors []*Vendor, name string, number int) *Vendor {
	for _, vendor := range vendors {
		if vendor.Name == name || vendor.Number == number {
			return vendor
		}
	}
	return nil
}
