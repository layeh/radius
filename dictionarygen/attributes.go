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
	if !attr.HasTag() {
		p(w, `func `, ident, `_Add(p *radius.Packet, value []byte) (err error) {`)
	} else {
		p(w, `func `, ident, `_Add(p *radius.Packet, tag byte, value []byte) (err error) {`)
	}
	if attr.Size.Valid {
		p(w, `	if len(value) != `, strconv.Itoa(attr.Size.Int), ` {`)
		p(w, `		err = errors.New("invalid value length")`)
		p(w, `		return`)
		p(w, `	}`)
	}
	p(w, `	var a radius.Attribute`)
	if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptUserPassword {
		p(w, `	a, err = radius.NewUserPassword(value, p.Secret, p.CryptoAuthenticator[:])`)
	} else if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptTunnelPassword {
		p(w, `	var salt [2]byte`)
		p(w, `	_, err = rand.Read(salt[:])`)
		p(w, `	if err != nil {`)
		p(w, `		return`)
		p(w, `	}`)
		p(w, `	salt[0] |= 1 << 7`) // RFC 2868 § 3.5
		p(w, `	a, err = radius.NewTunnelPassword(value, salt[:], p.Secret, p.CryptoAuthenticator[:])`)
	} else {
		p(w, `	a, err = radius.NewBytes(value)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if attr.HasTag() {
		p(w, `	if tag <= 0x1F {`)
		p(w, `		a = append(radius.Attribute{tag}, a...)`)
		p(w, `	}`)
	}
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_AddString(p *radius.Packet, value string) (err error) {`)
	} else {
		p(w, `func `, ident, `_AddString(p *radius.Packet, tag byte, value string) (err error) {`)
	}
	if attr.Size.Valid {
		p(w, `	if len(value) != `, strconv.Itoa(attr.Size.Int), ` {`)
		p(w, `		err = errors.New("invalid value length")`)
		p(w, `		return`)
		p(w, `	}`)
	}
	p(w, `	var a radius.Attribute`)
	if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptUserPassword {
		p(w, `	a, err = radius.NewUserPassword([]byte(value), p.Secret, p.CryptoAuthenticator[:])`)
	} else if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptTunnelPassword {
		p(w, `	var salt [2]byte`)
		p(w, `	_, err = rand.Read(salt[:])`)
		p(w, `	if err != nil {`)
		p(w, `		return`)
		p(w, `	}`)
		p(w, `	salt[0] |= 1 << 7`) // RFC 2868 § 3.5
		p(w, `	a, err = radius.NewTunnelPassword([]byte(value), salt[:], p.Secret, p.CryptoAuthenticator[:])`)
	} else {
		p(w, `	a, err = radius.NewString(value)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if attr.HasTag() {
		p(w, `	if tag <= 0x1F {`)
		p(w, `		a = append(radius.Attribute{tag}, a...)`)
		p(w, `	}`)
	}
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_Get(p *radius.Packet) (value []byte) {`)
		p(w, `	value, _ = `, ident, `_Lookup(p)`)
	} else {
		p(w, `func `, ident, `_Get(p *radius.Packet) (tag byte, value []byte) {`)
		p(w, `	tag, value, _ = `, ident, `_Lookup(p)`)
	}
	p(w, `	return`)
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_GetString(p *radius.Packet) (value string) {`)
		p(w, `	value, _ = `, ident, `_LookupString(p)`)
	} else {
		p(w, `func `, ident, `_GetString(p *radius.Packet) (tag byte, value string) {`)
		p(w, `	tag, value, _ = `, ident, `_LookupString(p)`)
	}
	p(w, `	return`)
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_Gets(p *radius.Packet) (values [][]byte, err error) {`)
	} else {
		p(w, `func `, ident, `_Gets(p *radius.Packet) (tags []byte, values [][]byte, err error) {`)
	}
	p(w, `	var i []byte`)
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, strconv.Itoa(attr.OID[0]), `) {`)
	} else {
		p(w, `	for _, avp := range p.Attributes {`)
		p(w, `		if avp.Type != `, ident, `_Type {`)
		p(w, `			continue`)
		p(w, `		}`)
		p(w, `		attr := avp.Attribute`)
	}
	if attr.HasTag() {
		p(w, `		var tag byte`)
		p(w, `		if len(attr) >= 1 && attr[0] <= 0x1F {`)
		p(w, `			tag = attr[0]`)
		p(w, `			attr = attr[1:]`)
		p(w, `		}`)
	}
	if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptUserPassword {
		p(w, `		i, err = radius.UserPassword(attr, p.Secret, p.CryptoAuthenticator[:])`)
	} else if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptTunnelPassword {
		p(w, `		i, _, err = radius.TunnelPassword(attr, p.Secret, p.CryptoAuthenticator[:])`)
	} else {
		p(w, `		i = radius.Bytes(attr)`)
	}
	if attr.Size.Valid {
		p(w, `		if err == nil && len(i) != `, strconv.Itoa(attr.Size.Int), ` {`)
		p(w, `			err = errors.New("invalid value length")`)
		p(w, `		}`)
	}
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, i)`)
	if attr.HasTag() {
		p(w, `		tags = append(tags, tag)`)
	}
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_GetStrings(p *radius.Packet) (values []string, err error) {`)
	} else {
		p(w, `func `, ident, `_GetStrings(p *radius.Packet) (tags []byte, values []string, err error) {`)
	}
	p(w, `	var i string`)
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, strconv.Itoa(attr.OID[0]), `) {`)
	} else {
		p(w, `	for _, avp := range p.Attributes {`)
		p(w, `		if avp.Type != `, ident, `_Type {`)
		p(w, `			continue`)
		p(w, `		}`)
		p(w, `		attr := avp.Attribute`)
	}
	if attr.HasTag() {
		p(w, `		var tag byte`)
		p(w, `		if len(attr) >= 1 && attr[0] <= 0x1F {`)
		p(w, `			tag = attr[0]`)
		p(w, `			attr = attr[1:]`)
		p(w, `		}`)
	}
	if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptUserPassword {
		p(w, `		var up []byte`)
		p(w, `		up, err = radius.UserPassword(attr, p.Secret, p.CryptoAuthenticator[:])`)
		p(w, `		if err == nil {`)
		p(w, `			i = string(up)`)
		p(w, `		}`)
	} else if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptTunnelPassword {
		p(w, `		var up []byte`)
		p(w, `		up, _, err = radius.TunnelPassword(attr, p.Secret, p.CryptoAuthenticator[:])`)
		p(w, `		if err == nil {`)
		p(w, `			i = string(up)`)
		p(w, `		}`)
	} else {
		p(w, `		i = radius.String(attr)`)
	}
	if attr.Size.Valid {
		p(w, `		if err == nil && len(i) != `, strconv.Itoa(attr.Size.Int), ` {`)
		p(w, `			err = errors.New("invalid value length")`)
		p(w, `		}`)
	}
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, i)`)
	if attr.HasTag() {
		p(w, `		tags = append(tags, tag)`)
	}
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_Lookup(p *radius.Packet) (value []byte, err error) {`)
	} else {
		p(w, `func `, ident, `_Lookup(p *radius.Packet) (tag byte, value []byte, err error) {`)
	}
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	if attr.HasTag() {
		p(w, `	if len(a) >= 1 && a[0] <= 0x1F {`)
		p(w, `		tag = a[0]`)
		p(w, `		a = a[1:]`)
		p(w, `	}`)
	}
	if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptUserPassword {
		p(w, `	value, err = radius.UserPassword(a, p.Secret, p.CryptoAuthenticator[:])`)
	} else if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptTunnelPassword {
		p(w, `	value, _, err = radius.TunnelPassword(a, p.Secret, p.CryptoAuthenticator[:])`)
	} else {
		p(w, `	value = radius.Bytes(a)`)
	}
	if attr.Size.Valid {
		p(w, `	if err == nil && len(value) != `, strconv.Itoa(attr.Size.Int), ` {`)
		p(w, `		err = errors.New("invalid value length")`)
		p(w, `	}`)
	}
	p(w, `	return`)
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_LookupString(p *radius.Packet) (value string, err error) {`)
	} else {
		p(w, `func `, ident, `_LookupString(p *radius.Packet) (tag byte, value string, err error) {`)
	}
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	if attr.HasTag() {
		p(w, `	if len(a) >= 1 && a[0] <= 0x1F {`)
		p(w, `		tag = a[0]`)
		p(w, `		a = a[1:]`)
		p(w, `	}`)
	}
	if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptUserPassword {
		p(w, `	var b []byte`)
		p(w, `	b, err = radius.UserPassword(a, p.Secret, p.CryptoAuthenticator[:])`)
		p(w, `	if err == nil {`)
		p(w, `		value = string(b)`)
		p(w, `	}`)
	} else if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptTunnelPassword {
		p(w, `		var b []byte`)
		p(w, `		b, _, err = radius.TunnelPassword(a, p.Secret, p.CryptoAuthenticator[:])`)
		p(w, `		if err == nil {`)
		p(w, `			value = string(b)`)
		p(w, `		}`)
	} else {
		p(w, `	value = radius.String(a)`)
	}
	if attr.Size.Valid {
		p(w, `	if err == nil && len(value) != `, strconv.Itoa(attr.Size.Int), ` {`)
		p(w, `		err = errors.New("invalid value length")`)
		p(w, `	}`)
	}
	p(w, `	return`)
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_Set(p *radius.Packet, value []byte) (err error) {`)
	} else {
		p(w, `func `, ident, `_Set(p *radius.Packet, tag byte, value []byte) (err error) {`)
	}
	if attr.Size.Valid {
		p(w, `	if len(value) != `, strconv.Itoa(attr.Size.Int), ` {`)
		p(w, `		err = errors.New("invalid value length")`)
		p(w, `		return`)
		p(w, `	}`)
	}
	p(w, `	var a radius.Attribute`)
	if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptUserPassword {
		p(w, `	a, err = radius.NewUserPassword(value, p.Secret, p.CryptoAuthenticator[:])`)
	} else if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptTunnelPassword {
		p(w, `	var salt [2]byte`)
		p(w, `	_, err = rand.Read(salt[:])`)
		p(w, `	if err != nil {`)
		p(w, `		return`)
		p(w, `	}`)
		p(w, `	salt[0] |= 1 << 7`) // RFC 2868 § 3.5
		p(w, `	a, err = radius.NewTunnelPassword(value, salt[:], p.Secret, p.CryptoAuthenticator[:])`)
	} else {
		p(w, `	a, err = radius.NewBytes(value)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if attr.HasTag() {
		p(w, `	if tag <= 0x1F {`)
		p(w, `		a = append(radius.Attribute{tag}, a...)`)
		p(w, `	}`)
	}
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_SetString(p *radius.Packet, value string) (err error) {`)
	} else {
		p(w, `func `, ident, `_SetString(p *radius.Packet, tag byte, value string) (err error) {`)
	}
	if attr.Size.Valid {
		p(w, `	if len(value) != `, strconv.Itoa(attr.Size.Int), ` {`)
		p(w, `		err = errors.New("invalid value length")`)
		p(w, `		return`)
		p(w, `	}`)
	}
	p(w, `	var a radius.Attribute`)
	if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptUserPassword {
		p(w, `	a, err = radius.NewUserPassword([]byte(value), p.Secret, p.CryptoAuthenticator[:])`)
	} else if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptTunnelPassword {
		p(w, `	var salt [2]byte`)
		p(w, `	_, err = rand.Read(salt[:])`)
		p(w, `	if err != nil {`)
		p(w, `		return`)
		p(w, `	}`)
		p(w, `	salt[0] |= 1 << 7`) // RFC 2868 § 3.5
		p(w, `	a, err = radius.NewTunnelPassword([]byte(value), salt[:], p.Secret, p.CryptoAuthenticator[:])`)
	} else {
		p(w, `	a, err = radius.NewString(value)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if attr.HasTag() {
		p(w, `	if tag <= 0x1F {`)
		p(w, `		a = append(radius.Attribute{tag}, a...)`)
		p(w, `	}`)
	}
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Del(p *radius.Packet) {`)
	if vendor != nil {
		p(w, `	_`, vendorIdent, `_DelVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	p.Attributes.Del(`, ident, `_Type)`)
	}
	p(w, `}`)
}

func (g *Generator) genAttributeStringOctetsConcat(w io.Writer, attr *dictionary.Attribute) {
	ident := identifier(attr.Name)

	p(w)
	p(w, `func `, ident, `_Get(p *radius.Packet) (value []byte) {`)
	p(w, `	value, _ = `, ident, `_Lookup(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_GetString(p *radius.Packet) (value string) {`)
	p(w, `	value, _ = `, ident, `_LookupString(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Lookup(p *radius.Packet) (value []byte, err error) {`)
	p(w, `	var i []byte`)
	p(w, `	var valid bool`)
	p(w, `	for _, avp := range p.Attributes {`)
	p(w, `		if avp.Type != `, ident, `_Type {`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		attr := avp.Attribute`)
	p(w, `		i = radius.Bytes(attr)`)
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		value = append(value, i...)`)
	p(w, `		valid = true`)
	p(w, `	}`)
	p(w, `	if !valid {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_LookupString(p *radius.Packet) (value string, err error) {`)
	p(w, `	var i string`)
	p(w, `	var valid bool`)
	p(w, `	for _, avp := range p.Attributes {`)
	p(w, `		if avp.Type != `, ident, `_Type {`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		attr := avp.Attribute`)
	p(w, `		i = radius.String(attr)`)
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		value += i`)
	p(w, `		valid = true`)
	p(w, `	}`)
	p(w, `	if !valid {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Set(p *radius.Packet, value []byte) (err error) {`)
	p(w, `	const maximumChunkSize = 253`)
	p(w, `	var attrs []*radius.AVP`)
	p(w, `	for len(value) > 0 {`)
	p(w, `		var a radius.Attribute`)
	p(w, `		n := len(value)`)
	p(w, `		if n > maximumChunkSize {`)
	p(w, `			n = maximumChunkSize`)
	p(w, `		}`)
	p(w, `		a, err = radius.NewBytes(value[:n])`)
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		attrs = append(attrs, &radius.AVP{`)
	p(w, `			Type:      `, ident, `_Type,`)
	p(w, `			Attribute: a,`)
	p(w, `		})`)
	p(w, `		value = value[n:]`)
	p(w, `	}`)
	p(w, `	p.Attributes = append(p.Attributes, attrs...)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_SetString(p *radius.Packet, value string) (err error) {`)
	p(w, `	const maximumChunkSize = 253`)
	p(w, `	var attrs []*radius.AVP`)
	p(w, `	for len(value) > 0 {`)
	p(w, `		var a radius.Attribute`)
	p(w, `		n := len(value)`)
	p(w, `		if n > maximumChunkSize {`)
	p(w, `			n = maximumChunkSize`)
	p(w, `		}`)
	p(w, `		a, err = radius.NewString(value[:n])`)
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		attrs = append(attrs, &radius.AVP{`)
	p(w, `			Type:      `, ident, `_Type,`)
	p(w, `			Attribute: a,`)
	p(w, `		})`)
	p(w, `		value = value[n:]`)
	p(w, `	}`)
	p(w, `	p.Attributes = append(p.Attributes, attrs...)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Del(p *radius.Packet) {`)
	p(w, `	p.Attributes.Del(`, ident, `_Type)`)
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

	genEncryptAttribute(w, attr.FlagEncrypt)

	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return`)
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
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, strconv.Itoa(attr.OID[0]), `) {`)
	} else {
		p(w, `	for _, avp := range p.Attributes {`)
		p(w, `		if avp.Type != `, ident, `_Type {`)
		p(w, `			continue`)
		p(w, `		}`)
		p(w, `		attr := avp.Attribute`)
	}

	genDecryptAttributes(w, attr.FlagEncrypt)

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
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)

	genDecryptAttribute(w, attr.FlagEncrypt)

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

	genEncryptAttribute(w, attr.FlagEncrypt)

	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Del(p *radius.Packet) {`)
	if vendor != nil {
		p(w, `	_`, vendorIdent, `_DelVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	p.Attributes.Del(`, ident, `_Type)`)
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
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return`)
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
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, strconv.Itoa(attr.OID[0]), `) {`)
	} else {
		p(w, `	for _, avp := range p.Attributes {`)
		p(w, `		if avp.Type != `, ident, `_Type {`)
		p(w, `			continue`)
		p(w, `		}`)
		p(w, `		attr := avp.Attribute`)
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
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
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
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Del(p *radius.Packet) {`)
	if vendor != nil {
		p(w, `	_`, vendorIdent, `_DelVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	p.Attributes.Del(`, ident, `_Type)`)
	}
	p(w, `}`)
}

func (g *Generator) genAttributeIPv6Prefix(w io.Writer, attr *dictionary.Attribute, vendor *dictionary.Vendor) {
	ident := identifier(attr.Name)
	var vendorIdent string
	if vendor != nil {
		vendorIdent = identifier(vendor.Name)
	}

	p(w)
	p(w, `func `, ident, `_Add(p *radius.Packet, value *net.IPNet) (err error) {`)
	p(w, `	var a radius.Attribute`)
	p(w, `	a, err = radius.NewIPv6Prefix(value)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Get(p *radius.Packet) (value *net.IPNet) {`)
	p(w, `	value, _ = `, ident, `_Lookup(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Gets(p *radius.Packet) (values []*net.IPNet, err error) {`)
	p(w, `	var i *net.IPNet`)
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, strconv.Itoa(attr.OID[0]), `) {`)
	} else {
		p(w, `	for _, avp := range p.Attributes {`)
		p(w, `		if avp.Type != `, ident, `_Type {`)
		p(w, `			continue`)
		p(w, `		}`)
		p(w, `		attr := avp.Attribute`)
	}
	p(w, `		i, err = radius.IPv6Prefix(attr)`)
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, i)`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Lookup(p *radius.Packet) (value *net.IPNet, err error) {`)
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	value, err = radius.IPv6Prefix(a)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Set(p *radius.Packet, value *net.IPNet) (err error) {`)
	p(w, `	var a radius.Attribute`)
	p(w, `	a, err = radius.NewIPv6Prefix(value)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Del(p *radius.Packet) {`)
	if vendor != nil {
		p(w, `	_`, vendorIdent, `_DelVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	p.Attributes.Del(`, ident, `_Type)`)
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
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return`)
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
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, strconv.Itoa(attr.OID[0]), `) {`)
	} else {
		p(w, `	for _, avp := range p.Attributes {`)
		p(w, `		if avp.Type != `, ident, `_Type {`)
		p(w, `			continue`)
		p(w, `		}`)
		p(w, `		attr := avp.Attribute`)
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
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
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
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Del(p *radius.Packet) {`)
	if vendor != nil {
		p(w, `	_`, vendorIdent, `_DelVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	p.Attributes.Del(`, ident, `_Type)`)
	}
	p(w, `}`)
}

func (g *Generator) genAttributeInteger(w io.Writer, attr *dictionary.Attribute, allValues []*dictionary.Value, bitsize int, vendor *dictionary.Vendor) {
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
	if bitsize == 64 {
		p(w, `type `, ident, ` uint64`)
	} else if bitsize == 16 {
		p(w, `type `, ident, ` uint16`)
	} else { // 32
		p(w, `type `, ident, ` uint32`)
	}

	// Values
	if len(values) > 0 {
		p(w)
		p(w, `const (`)
		for _, value := range values {
			valueIdent := identifier(value.Name)
			p(w, `	`, ident, `_Value_`, valueIdent, ` `, ident, ` = `, strconv.FormatUint(value.Number, 10))
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
	p(w, `	return "`, ident, `(" + strconv.FormatUint(uint64(a), 10) + ")"`)
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_Add(p *radius.Packet, value `, ident, `) (err error) {`)
	} else {
		p(w, `func `, ident, `_Add(p *radius.Packet, tag byte, value `, ident, `) (err error) {`)
	}
	if bitsize == 64 {
		p(w, `	a := radius.NewInteger64(uint64(value))`)
	} else if bitsize == 16 {
		p(w, `	a := radius.NewShort(uint16(value))`)
	} else { // 32
		p(w, `	a := radius.NewInteger(uint32(value))`)
	}
	if attr.HasTag() {
		p(w, `		if tag >= 0x01 && tag <= 0x1F {`)
		p(w, `			a[0] = tag`)
		p(w, `		} else {`)
		p(w, `			a[0] = 0x00`)
		p(w, `		}`)
	}

	genEncryptAttribute(w, attr.FlagEncrypt)

	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_Get(p *radius.Packet) (value `, ident, `) {`)
		p(w, `	value, _ = `, ident, `_Lookup(p)`)
	} else {
		p(w, `func `, ident, `_Get(p *radius.Packet) (tag byte, value `, ident, `) {`)
		p(w, `	tag, value, _ = `, ident, `_Lookup(p)`)
	}
	p(w, `	return`)
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_Gets(p *radius.Packet) (values []`, ident, `, err error) {`)
	} else {
		p(w, `func `, ident, `_Gets(p *radius.Packet) (tags []byte, values []`, ident, `, err error) {`)
	}
	if bitsize == 64 {
		p(w, `	var i uint64`)
	} else if bitsize == 16 {
		p(w, `	var i uint16`)
	} else { // 32
		p(w, `	var i uint32`)
	}
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, strconv.Itoa(attr.OID[0]), `) {`)
	} else {
		p(w, `	for _, avp := range p.Attributes {`)
		p(w, `		if avp.Type != `, ident, `_Type {`)
		p(w, `			continue`)
		p(w, `		}`)
		p(w, `		attr := avp.Attribute`)
	}
	if attr.HasTag() {
		p(w, `		var tag byte`)
		p(w, `		if len(attr) >= 1 && attr[0] <= 0x1F {`)
		p(w, `			tag = attr[0]`)
		p(w, `			attr[0] = 0x00`)
		p(w, `		}`)
	}
	genDecryptAttributes(w, attr.FlagEncrypt)
	if bitsize == 64 {
		p(w, `		i, err = radius.Integer64(attr)`)
	} else if bitsize == 16 {
		p(w, `		i, err = radius.Short(attr)`)
	} else { // 32
		p(w, `		i, err = radius.Integer(attr)`)
	}
	p(w, `		if err != nil {`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, `, ident, `(i))`)
	if attr.HasTag() {
		p(w, `		tags = append(tags, tag)`)
	}
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_Lookup(p *radius.Packet) (value `, ident, `, err error) {`)
	} else {
		p(w, `func `, ident, `_Lookup(p *radius.Packet) (tag byte, value `, ident, `, err error) {`)
	}
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	if attr.HasTag() {
		p(w, `	if len(a) >= 1 && a[0] <= 0x1F {`)
		p(w, `		tag = a[0]`)
		p(w, `		a[0] = 0x00`)
		p(w, `	}`)
	}

	genDecryptAttribute(w, attr.FlagEncrypt)

	if bitsize == 64 {
		p(w, `	var i uint64`)
		p(w, `	i, err = radius.Integer64(a)`)
	} else if bitsize == 16 {
		p(w, `	var i uint16`)
		p(w, `	i, err = radius.Short(a)`)
	} else { // 32
		p(w, `	var i uint32`)
		p(w, `	i, err = radius.Integer(a)`)
	}
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	value = `, ident, `(i)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	if !attr.HasTag() {
		p(w, `func `, ident, `_Set(p *radius.Packet, value `, ident, `) (err error) {`)
	} else {
		p(w, `func `, ident, `_Set(p *radius.Packet, tag byte, value `, ident, `) (err error) {`)
	}
	if bitsize == 64 {
		p(w, `	a := radius.NewInteger64(uint64(value))`)
	} else if bitsize == 16 {
		p(w, `	a := radius.NewShort(uint16(value))`)
	} else { // 32
		p(w, `	a := radius.NewInteger(uint32(value))`)
	}

	if attr.HasTag() {
		p(w, `		if tag >= 0x01 && tag <= 0x1F {`)
		p(w, `			a[0] = tag`)
		p(w, `		} else {`)
		p(w, `			a[0] = 0x00`)
		p(w, `		}`)
	}

	genEncryptAttribute(w, attr.FlagEncrypt)

	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Del(p *radius.Packet) {`)
	if vendor != nil {
		p(w, `	_`, vendorIdent, `_DelVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	p.Attributes.Del(`, ident, `_Type)`)
	}
	p(w, `}`)
}

func genEncryptAttribute(w io.Writer, encryptFlag dictionary.IntFlag) {
	if encryptFlag.Valid && encryptFlag.Int == dictionary.EncryptUserPassword {
		p(w, `  a, err = radius.NewUserPassword(a, p.Secret, p.CryptoAuthenticator[:])`)
		p(w, `	if err != nil {`)
		p(w, `		return`)
		p(w, `	}`)
	} else if encryptFlag.Valid && encryptFlag.Int == dictionary.EncryptTunnelPassword {
		p(w, `  var salt [2]byte`)
		p(w, `  _, err = rand.Read(salt[:])`)
		p(w, `  if err != nil {`)
		p(w, `          return`)
		p(w, `  }`)
		p(w, `  salt[0] |= 1 << 7`) // RFC 2868 § 3.5
		p(w, `  a, err = radius.NewTunnelPassword(a, salt[:], p.Secret, p.CryptoAuthenticator[:])`)
		p(w, `	if err != nil {`)
		p(w, `		return`)
		p(w, `	}`)
	}
}

func genDecryptAttribute(w io.Writer, encryptFlag dictionary.IntFlag) {
	if encryptFlag.Valid && encryptFlag.Int == dictionary.EncryptUserPassword {
		p(w, `	a, err = radius.UserPassword(a, p.Secret, p.CryptoAuthenticator[:])`)
		p(w, `	if err != nil {`)
		p(w, `		return`)
		p(w, `	}`)
	} else if encryptFlag.Valid && encryptFlag.Int == dictionary.EncryptTunnelPassword {
		p(w, `	a, _, err = radius.TunnelPassword(a, p.Secret, p.CryptoAuthenticator[:])`)
		p(w, `	if err != nil {`)
		p(w, `		return`)
		p(w, `	}`)
	}
}

func genDecryptAttributes(w io.Writer, encryptFlag dictionary.IntFlag) {
	if encryptFlag.Valid && encryptFlag.Int == dictionary.EncryptUserPassword {
		p(w, `		attr, err = radius.UserPassword(attr, p.Secret, p.CryptoAuthenticator[:])`)
		p(w, `	    if err != nil {`)
		p(w, `		    return`)
		p(w, `	    }`)
	} else if encryptFlag.Valid && encryptFlag.Int == dictionary.EncryptTunnelPassword {
		p(w, `		attr, _, err = radius.TunnelPassword(attr, p.Secret, p.CryptoAuthenticator[:])`)
		p(w, `	    if err != nil {`)
		p(w, `		    return`)
		p(w, `	    }`)
	}
}

func (g *Generator) genAttributeByte(w io.Writer, attr *dictionary.Attribute, vendor *dictionary.Vendor) {
	ident := identifier(attr.Name)
	var vendorIdent string
	if vendor != nil {
		vendorIdent = identifier(vendor.Name)
	}

	p(w)
	p(w, `func `, ident, `_Add(p *radius.Packet, value byte) (err error) {`)
	p(w, `	a := radius.Attribute{value}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_AddVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Add(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Get(p *radius.Packet) (value byte) {`)
	p(w, `	value, _ = `, ident, `_Lookup(p)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Gets(p *radius.Packet) (values []byte, err error) {`)
	if attr.HasTag() {
		p(w, `	var tag byte`)
	}
	if vendor != nil {
		p(w, `	for _, attr := range _`, vendorIdent, `_GetsVendor(p, `, strconv.Itoa(attr.OID[0]), `) {`)
	} else {
		p(w, `	for _, avp := range p.Attributes {`)
		p(w, `		if avp.Type != `, ident, `_Type {`)
		p(w, `			continue`)
		p(w, `		}`)
		p(w, `		attr := avp.Attribute`)
	}
	p(w, `		if len(attr) != 1 {`)
	p(w, `			err = errors.New("invalid byte")`)
	p(w, `			return`)
	p(w, `		}`)
	p(w, `		values = append(values, attr[0])`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Lookup(p *radius.Packet) (value byte, err error) {`)
	if vendor != nil {
		p(w, `	a, ok  := _`, vendorIdent, `_LookupVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	a, ok  := p.Lookup(`, ident, `_Type)`)
	}
	p(w, `	if !ok {`)
	p(w, `		err = radius.ErrNoAttribute`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	if len(a) != 1 {`)
	p(w, `		err = errors.New("invalid byte")`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	value = a[0]`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Set(p *radius.Packet, value byte) (err error) {`)
	p(w, `	a := radius.Attribute{value}`)
	if vendor != nil {
		p(w, `	return _`, vendorIdent, `_SetVendor(p, `, strconv.Itoa(attr.OID[0]), `, a)`)
	} else {
		p(w, `	p.Set(`, ident, `_Type, a)`)
		p(w, `	return`)
	}
	p(w, `}`)

	p(w)
	p(w, `func `, ident, `_Del(p *radius.Packet) {`)
	if vendor != nil {
		p(w, `	_`, vendorIdent, `_DelVendor(p, `, strconv.Itoa(attr.OID[0]), `)`)
	} else {
		p(w, `	p.Attributes.Del(`, ident, `_Type)`)
	}
	p(w, `}`)
}
