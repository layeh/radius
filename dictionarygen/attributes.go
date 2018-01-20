package dictionarygen

import (
	"io"
	"strconv"

	"layeh.com/radius/dictionary"
)

func (g *Generator) genAttributeStringOctets(w io.Writer, attr *dictionary.Attribute) {
	ident := identifier(attr.Name)

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
	p(w, `	p.Add(`, ident, `_Type, a)`)
	p(w, `	return nil`)
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
	p(w, `	p.Add(`, ident, `_Type, a)`)
	p(w, `	return nil`)
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
	p(w, `	for _, attr := range p.Attributes[`, ident, `_Type] {`)
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
	p(w, `	for _, attr := range p.Attributes[`, ident, `_Type] {`)
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
	p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
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
	p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
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
	p(w, `	p.Set(`, ident, `_Type, a)`)
	p(w, `	return`)
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
	p(w, `	p.Set(`, ident, `_Type, a)`)
	p(w, `	return`)
	p(w, `}`)
}

func (g *Generator) genAttributeIPAddr(w io.Writer, attr *dictionary.Attribute) {
	ident := identifier(attr.Name)

	p(w)
	p(w, `func `, ident, `_Add(p *radius.Packet, value net.IP) (err error) {`)
	p(w, `	var a radius.Attribute`)
	p(w, `	a, err = radius.NewIPAddr(value)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	p.Add(`, ident, `_Type, a)`)
	p(w, `	return nil`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Get(p *radius.Packet) (value net.IP) {`)
	p(w, `	value, _ = `, ident, `_Lookup(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Gets(p *radius.Packet) (values []net.IP, err error) {`)
	p(w, `	var i net.IP`)
	p(w, `	for _, attr := range p.Attributes[`, ident, `_Type] {`)
	p(w, `		i, err = radius.IPAddr(attr)`)
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, i)`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Lookup(p *radius.Packet) (value net.IP, err error) {`)
	p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	value, err = radius.IPAddr(a)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Set(p *radius.Packet, value net.IP) (err error) {`)
	p(w, `	var a radius.Attribute`)
	p(w, `	a, err = radius.NewIPAddr(value)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	p.Set(`, ident, `_Type, a)`)
	p(w, `	return`)
	p(w, `}`)
}

func (g *Generator) genAttributeInteger(w io.Writer, attr *dictionary.Attribute, allValues []*dictionary.Value) {
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
	p(w, `func `, ident, `_Add(p *radius.Packet, value `, ident, `) {`)
	p(w, `	a := radius.NewInteger(uint32(value))`)
	p(w, `	p.Add(`, ident, `_Type, a)`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Get(p *radius.Packet) (value `, ident, `) {`)
	p(w, `	value, _ = `, ident, `_Lookup(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Gets(p *radius.Packet) (values []`, ident, `, err error) {`)
	p(w, `	var i uint32`)
	p(w, `	for _, attr := range p.Attributes[`, ident, `_Type] {`)
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
	p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
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
	p(w, `func `, ident, `_Set(p *radius.Packet, value `, ident, `) {`)
	p(w, `	a := radius.NewInteger(uint32(value))`)
	p(w, `	p.Set(`, ident, `_Type, a)`)
	p(w, `}`)
}
