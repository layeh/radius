package radius

import (
	"errors"
	"sync"
	"bytes"
)

// Vendor is the Vendor-Specific dictionary.
var Vendor  *DictionaryVendor

type dictVendorEntry struct {
	Type     byte
	VendorID uint32
	Name     string
	Codec    AttributeCodec
}

type vendorEntry struct {
	VendorID         uint32
	Name             string
	attributesByType [256]*dictVendorEntry
}

// Dictionary stores mappings between vendor-attribute names and types and
// AttributeCodecs.
type DictionaryVendor struct {
	mu               sync.RWMutex
	vendorID         map[uint32]*vendorEntry
	attributesByName map[string]*dictVendorEntry
}

// Register registers the AttributeCodec for the given vendor-attribute name and type.
func (d *DictionaryVendor) Register(vendorID uint32, name string, t byte, codec AttributeCodec) error {
	d.mu.Lock()
	entry := &dictVendorEntry{
		Type:  t,
		VendorID: vendorID,
		Name:  name,
		Codec: codec,
	}

	if d.vendorID == nil {
		d.vendorID = make(map[uint32]*vendorEntry)
	}

	if d.vendorID[vendorID] == nil {
		vEntry := &vendorEntry{
			VendorID: vendorID,
		}

		d.vendorID[vendorID] = vEntry
	}
	d.vendorID[vendorID].attributesByType[t] = entry

	if d.attributesByName == nil {
		d.attributesByName = make(map[string]*dictVendorEntry)
	}
	d.attributesByName[name] = entry
	d.mu.Unlock()
	return nil
}

// MustRegister is a helper for Register that panics if it returns an error.
func (d *DictionaryVendor) MustRegister(vendorID uint32, name string, t byte, codec AttributeCodec) {
	if err := d.Register(vendorID, name, t, codec); err != nil {
		panic(err)
	}
}

func (d *DictionaryVendor) get(name string) (vendorID uint32, t byte, codec AttributeCodec, ok bool) {
	d.mu.RLock()
	entry := d.attributesByName[name]
	d.mu.RUnlock()
	if entry == nil {
		return
	}
	t = entry.Type
	vendorID = entry.VendorID
	codec = entry.Codec
	ok = true
	return
}

// Attr returns a new *Attribute whose type is registered under the given
// name.
//
// If name is not registered, nil and an error is returned.
func (d *DictionaryVendor) Attr(name string, value interface{}) (*Attribute, error) {
	vendorID, t, _, ok := d.get(name)
	if !ok {
		return nil, errors.New("radius: attribute name not registered")
	}

	codec := d.Codec(vendorID, t)
	wire, err := codec.Encode(nil, value)
	if err != nil {
		return nil, err
	}

	var bufferAttrs bytes.Buffer
	bufferAttrs.WriteByte(t)
	bufferAttrs.WriteByte(byte(len(wire) + 2))
	bufferAttrs.Write(wire)

	encodedValue := VendorSpecific {
		VendorID: vendorID,
		Data: bufferAttrs.Bytes(),
	}

	return &Attribute{
		Type: 26,
		VendorID: vendorID,
		Value: encodedValue,
	}, nil
}

// MustAttr is a helper for Attr that panics if Attr were to return an error.
func (d *DictionaryVendor) MustAttr(name string, value interface{}) *Attribute {
	attr, err := d.Attr(name, value)
	if err != nil {
		panic(err)
	}
	return attr
}

// Name returns the registered name for the given attribute type. ok is false
// if the given type is not registered.
func (d *DictionaryVendor) Name(vendorID uint32, t byte) (name string, ok bool) {
	d.mu.RLock()
	var entry *dictVendorEntry

	if d.vendorID[vendorID] != nil &&
	   d.vendorID[vendorID].attributesByType[t] != nil {
		entry = d.vendorID[vendorID].attributesByType[t]
	}
	d.mu.RUnlock()
	if entry == nil {
		return
	}
	name = entry.Name
	ok = true
	return
}

// Type returns the registered type for the given attribute name. ok is false
// if the given name is not registered.
func (d *DictionaryVendor) Type(name string) (t byte, ok bool) {
	d.mu.RLock()
	entry := d.attributesByName[name]
	d.mu.RUnlock()
	if entry == nil {
		return
	}
	t = entry.Type
	ok = true
	return
}

// Codec returns the AttributeCodec for the given registered type. nil is
// returned if the given type is not registered.
func (d *DictionaryVendor) Codec(vendorID uint32, t byte) AttributeCodec {
	d.mu.RLock()
	var entry *dictVendorEntry

	if d.vendorID[vendorID] != nil &&
	   d.vendorID[vendorID].attributesByType[t] != nil {
		entry = d.vendorID[vendorID].attributesByType[t]
	}
	d.mu.RUnlock()
	if entry == nil {
		return AttributeUnknown
	}
	return entry.Codec
}

// Name returns the registered attribute for the given attribute type.
func (d *DictionaryVendor) AttrByType(vendorID uint32, t byte) (attribute *dictVendorEntry) {
	d.mu.RLock()
	var entry *dictVendorEntry

	if d.vendorID[vendorID] != nil &&
	   d.vendorID[vendorID].attributesByType[t] != nil {
		entry = d.vendorID[vendorID].attributesByType[t]
	}
	d.mu.RUnlock()
	if entry == nil {
		return
	}
	attribute = entry
	return
}

func (d *DictionaryVendor) SubAttributes(vendorID uint32, data []byte) (attributes []*Attribute) {
	dataLength := len(data)
	if dataLength < 2 || dataLength > 249 {
		return
	}

	n := byte(0)
	for (n+2) < byte(dataLength) {
		aid := data[n:n+1][0]
		length := data[n+1:n+2][0]

		if entry := d.AttrByType(vendorID, aid); entry != nil {
			val := make([]byte, length - 2)
			copy(val, data[n+2:length])
			decoded, err := entry.Codec.Decode(nil, val)

			if err == nil {
				attr := &Attribute {
					Type: aid,
					VendorID: vendorID,
					Value: decoded,
				}

				attributes = append(attributes, attr)
			}
		}

		n = n + length
	}

	return
}
