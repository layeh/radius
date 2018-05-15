package dictionary

import "fmt"

func Merge(d1, d2 *Dictionary) (*Dictionary, error) {
	// TODO: correct vendor merging

	// Duplicate checks
	for _, attr := range d2.Attributes {
		existingAttr := AttributeByName(d1.Attributes, attr.Name)
		if existingAttr == nil {
			existingAttr = AttributeByOID(d1.Attributes, attr.OID)
		}

		if existingAttr != nil {
			return nil, fmt.Errorf("duplicate attribute %s (%s)", attr.Name, attr.OID)
		}
	}

	// Merge
	newDict := &Dictionary{
		Attributes: make([]*Attribute, 0, len(d1.Attributes)+len(d2.Attributes)),
		Values:     make([]*Value, 0, len(d1.Values)+len(d2.Values)),
		Vendors:    make([]*Vendor, 0, len(d1.Vendors)+len(d2.Vendors)), // TODO: incorrect
	}

	newDict.Attributes = append(newDict.Attributes, d1.Attributes...)
	newDict.Attributes = append(newDict.Attributes, d2.Attributes...)

	newDict.Values = append(newDict.Values, d1.Values...)
	newDict.Values = append(newDict.Values, d2.Values...)

	newDict.Vendors = append(newDict.Vendors, d1.Vendors...)
	newDict.Vendors = append(newDict.Vendors, d2.Vendors...)

	return newDict, nil
}

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
