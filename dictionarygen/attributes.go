package dictionarygen

import (
	"io"
	"net"
	"strconv"

	"layeh.com/radius/dictionary"
)

func (g *Generator) genAttributeStringOctets(w io.Writer, attr *dictionary.Attribute, vendor *dictionary.Vendor) {
	ident := identifier(attr.Name)
	var vendorIdent string
	if vendor != nil {
		vendorIdent = identifier(vendor.Name)
	}

	p(w)
	p(w, `func `, ident, `_Add(p *radius.Packet, value []byte) (err error) {`)
	p(w, `	var a radius.Attribute`)
	if attr.FlagEncrypt != nil && *attr.FlagEncrypt == 1 {
		p(w, `	a, err = radius.NewUserPassword(value, p.Secret, p.Authenticator[:])`)
	} else {
		p(w, `	a, err = radius.NewBytes(value)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return nil`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_AddString(p *radius.Packet, value string) (err error) {`)
	p(w, `	var a radius.Attribute`)
	if attr.FlagEncrypt != nil && *attr.FlagEncrypt == 1 {
		p(w, `	a, err = radius.NewUserPassword([]byte(value), p.Secret, p.Authenticator[:])`)
	} else {
		p(w, `	a, err = radius.NewString(value)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return nil`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Get(p *radius.Packet) (value []byte) {`)
	p(w, `	value, _ = `, ident, `_Lookup(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_GetString(p *radius.Packet) (value string) {`)
	p(w, `	return string(`, ident, `_Get(p))`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Gets(p *radius.Packet) (values [][]byte, err error) {`)
	p(w, `	var i []byte`)
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, attr.OID, `) {`)
	} else {
		p(w, `	for _, attr := range p.Attributes[`, ident, `_Type] {`)
	}
	if attr.FlagEncrypt != nil && *attr.FlagEncrypt == 1 {
		p(w, `		i, err = radius.UserPassword(attr, p.Secret, p.Authenticator[:])`)
	} else {
		p(w, `		i = radius.Bytes(attr)`)
	}
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, i)`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_GetStrings(p *radius.Packet) (values []string, err error) {`)
	p(w, `	var i string`)
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, attr.OID, `) {`)
	} else {
		p(w, `	for _, attr := range p.Attributes[`, ident, `_Type] {`)
	}
	if attr.FlagEncrypt != nil && *attr.FlagEncrypt == 1 {
		p(w, `		var up radius.Attribute`)
		p(w, `		up, err = radius.UserPassword(attr, p.Secret, p.Authenticator[:])`)
		p(w, `		if err == nil {`)
		p(w, `			i = string(up)`)
		p(w, `		}`)
	} else {
		p(w, `		i = radius.String(attr)`)
	}
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, i)`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Lookup(p *radius.Packet) (value []byte, err error) {`)
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, attr.OID, `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	if attr.FlagEncrypt != nil && *attr.FlagEncrypt == 1 {
		p(w, `	value, err = radius.UserPassword(a, p.Secret, p.Authenticator[:])`)
	} else {
		p(w, `	value = radius.Bytes(a)`)
	}
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_LookupString(p *radius.Packet) (value string, err error) {`)
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, attr.OID, `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	if attr.FlagEncrypt != nil && *attr.FlagEncrypt == 1 {
		p(w, `	var b []byte`)
		p(w, `	b, err = radius.UserPassword(a, p.Secret, p.Authenticator[:])`)
		p(w, `	if err == nil {`)
		p(w, `		value = string(b)`)
		p(w, `	}`)
	} else {
		p(w, `	value = radius.String(a)`)
	}
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Set(p *radius.Packet, value []byte) (err error) {`)
	p(w, `	var a radius.Attribute`)
	if attr.FlagEncrypt != nil && *attr.FlagEncrypt == 1 {
		p(w, `	a, err = radius.NewUserPassword(value, p.Secret, p.Authenticator[:])`)
	} else {
		p(w, `	a, err = radius.NewBytes(value)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_SetString(p *radius.Packet, value string) (err error) {`)
	p(w, `	var a radius.Attribute`)
	if attr.FlagEncrypt != nil && *attr.FlagEncrypt == 1 {
		p(w, `	a, err = radius.NewUserPassword([]byte(value), p.Secret, p.Authenticator[:])`)
	} else {
		p(w, `	a, err = radius.NewString(value)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)
}

func (g *Generator) genAttributeIPAddr(w io.Writer, attr *dictionary.Attribute, vendor *dictionary.Vendor, length int) {
	if length != net.IPv4len && length != net.IPv6len {
		panic("invalid length")
	}

	ident := identifier(attr.Name)
	var vendorIdent string
	if vendor != nil {
		vendorIdent = identifier(vendor.Name)
	}

	p(w)
	p(w, `func `, ident, `_Add(p *radius.Packet, value net.IP) (err error) {`)
	p(w, `	var a radius.Attribute`)
	if length == net.IPv4len {
		p(w, `	a, err = radius.NewIPAddr(value)`)
	} else {
		p(w, `	a, err = radius.NewIPv6Addr(value)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return nil`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Get(p *radius.Packet) (value net.IP) {`)
	p(w, `	value, _ = `, ident, `_Lookup(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Gets(p *radius.Packet) (values []net.IP, err error) {`)
	p(w, `	var i net.IP`)
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, attr.OID, `) {`)
	} else {
		p(w, `	for _, attr := range p.Attributes[`, ident, `_Type] {`)
	}
	if length == net.IPv4len {
		p(w, `		i, err = radius.IPAddr(attr)`)
	} else {
		p(w, `		i, err = radius.IPv6Addr(attr)`)
	}
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, i)`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Lookup(p *radius.Packet) (value net.IP, err error) {`)
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, attr.OID, `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	if length == net.IPv4len {
		p(w, `	value, err = radius.IPAddr(a)`)
	} else {
		p(w, `	value, err = radius.IPv6Addr(a)`)
	}
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Set(p *radius.Packet, value net.IP) (err error) {`)
	p(w, `	var a radius.Attribute`)
	if length == net.IPv4len {
		p(w, `	a, err = radius.NewIPAddr(value)`)
	} else {
		p(w, `	a, err = radius.NewIPv6Addr(value)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return nil`)
	}
	p(w, `}`)
}


func (g *Generator) genAttributeIFID(w io.Writer, attr *dictionary.Attribute, vendor *dictionary.Vendor) {
	ident := identifier(attr.Name)
	var vendorIdent string
	if vendor != nil {
		vendorIdent = identifier(vendor.Name)
	}

	p(w)
	p(w, `func `, ident, `_Add(p *radius.Packet, value net.HardwareAddr) (err error) {`)
	p(w, `	var a radius.Attribute`)
	p(w, `	a, err = radius.NewIFID(value)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return nil`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Get(p *radius.Packet) (value net.HardwareAddr) {`)
	p(w, `	value, _ = `, ident, `_Lookup(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Gets(p *radius.Packet) (values []net.HardwareAddr, err error) {`)
	p(w, `	var i net.HardwareAddr`)
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, attr.OID, `) {`)
	} else {
		p(w, `	for _, attr := range p.Attributes[`, ident, `_Type] {`)
	}
	p(w, `		i, err = radius.IFID(attr)`)
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, i)`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Lookup(p *radius.Packet) (value net.HardwareAddr, err error) {`)
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, attr.OID, `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	value, err = radius.IFID(a)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Set(p *radius.Packet, value net.HardwareAddr) (err error) {`)
	p(w, `	var a radius.Attribute`)
	p(w, `	a, err = radius.NewIFID(value)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return nil`)
	}
	p(w, `}`)
}

func (g *Generator) genAttributeDate(w io.Writer, attr *dictionary.Attribute, vendor *dictionary.Vendor) {
	ident := identifier(attr.Name)
	var vendorIdent string
	if vendor != nil {
		vendorIdent = identifier(vendor.Name)
	}

	p(w)
	p(w, `func `, ident, `_Add(p *radius.Packet, value time.Time) (err error) {`)
	p(w, `	var a radius.Attribute`)
	p(w, `	a, err = radius.NewDate(value)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return nil`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Get(p *radius.Packet) (value time.Time) {`)
	p(w, `	value, _ = `, ident, `_Lookup(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Gets(p *radius.Packet) (values []time.Time, err error) {`)
	p(w, `	var i time.Time`)
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, attr.OID, `) {`)
	} else {
		p(w, `	for _, attr := range p.Attributes[`, ident, `_Type] {`)
	}
	p(w, `		i, err = radius.Date(attr)`)
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, i)`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Lookup(p *radius.Packet) (value time.Time, err error) {`)
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, attr.OID, `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	value, err = radius.Date(a)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Set(p *radius.Packet, value time.Time) (err error) {`)
	p(w, `	var a radius.Attribute`)
	p(w, `	a, err = radius.NewDate(value)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return nil`)
	}
	p(w, `}`)
}

func (g *Generator) genAttributeInteger(w io.Writer, attr *dictionary.Attribute, allValues []*dictionary.Value, vendor *dictionary.Vendor) {
	var values []*dictionary.Value
	for _, value := range allValues {
		if value.Attribute == attr.Name {
			if len(values) > 0 && values[len(values)-1].Number == value.Number {
				values[len(values)-1] = value
			} else {
				values = append(values, value)
			}
		}
	}

	ident := identifier(attr.Name)
	var vendorIdent string
	if vendor != nil {
		vendorIdent = identifier(vendor.Name)
	}

	p(w)
	p(w, `type `, ident, ` uint32`)

	// Values
	if len(values) > 0 {
		p(w)
		p(w, `const (`)
		for _, value := range values {
			valueIdent := identifier(value.Name)
			p(w, `	`, ident, `_Value_`, valueIdent, ` `, ident, ` = `, strconv.Itoa(value.Number))
		}
		p(w, `)`)
	}

	p(w)
	p(w, `var `, ident, `_Strings = map[`, ident, `]string{`)
	for _, value := range values {
		valueIdent := identifier(value.Name)
		p(w, `	`, ident, `_Value_`, valueIdent, `: `, strconv.Quote(value.Name), `,`)
	}
	p(w, `}`)

	p(w)
	p(w, `func (a `, ident, `) String() string {`)
	p(w, `	if str, ok := `, ident, `_Strings[a]; ok {`)
	p(w, `		return str`)
	p(w, `	}`)
	p(w, `	return "`, ident, `(" + strconv.Itoa(int(a)) + ")"`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Add(p *radius.Packet, value `, ident, `) (err error) {`)
	p(w, `	a := radius.NewInteger(uint32(value))`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return nil`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Get(p *radius.Packet) (value `, ident, `) {`)
	p(w, `	value, _ = `, ident, `_Lookup(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Gets(p *radius.Packet) (values []`, ident, `, err error) {`)
	p(w, `	var i uint32`)
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, attr.OID, `) {`)
	} else {
		p(w, `	for _, attr := range p.Attributes[`, ident, `_Type] {`)
	}
	p(w, `		i, err = radius.Integer(attr)`)
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, `, ident, `(i))`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Lookup(p *radius.Packet) (value `, ident, `, err error) {`)
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, attr.OID, `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	var i uint32`)
	p(w, `	i, err = radius.Integer(a)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	value = `, ident, `(i)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Set(p *radius.Packet, value `, ident, `) (err error) {`)
	p(w, `	a := radius.NewInteger(uint32(value))`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, attr.OID, `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return nil`)
	}
	p(w, `}`)
}
