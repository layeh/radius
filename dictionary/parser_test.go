package dictionary

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestParser(t *testing.T) {
	parser := Parser{
		Opener: files,
	}

	d, err := parser.ParseFile("simple.dict")
	if err != nil {
		t.Fatal(err)
	}

	expected := &Dictionary{
		Attributes: []*Attribute{
			{
				Name: "User-Name",
				OID:  "1",
				Type: AttributeString,
			},
			{
				Name:        "User-Password",
				OID:         "2",
				Type:        AttributeOctets,
				FlagEncrypt: newIntPtr(1),
			},
			{
				Name: "Mode",
				OID:  "127",
				Type: AttributeInteger,
			},
			{
				Name: "ARAP-Challenge-Response",
				OID:  "84",
				Type: AttributeOctets,
				Size: newIntPtr(8),
			},
		},
		Values: []*Value{
			{
				Attribute: "Mode",
				Name:      "Full",
				Number:    1,
			},
			{
				Attribute: "Mode",
				Name:      "Half",
				Number:    2,
			},
		},
	}

	if !reflect.DeepEqual(d, expected) {
		t.Fatalf("got %s, expected %s", dictString(d), dictString(expected))
	}
}

func TestParser_recursiveinclude(t *testing.T) {
	parser := Parser{
		Opener: files,
	}

	d, err := parser.ParseFile("recursive_1.dict")
	pErr, ok := err.(*ParseError)
	if !ok || pErr == nil || d != nil {
		t.Fatalf("got %v, expected *ParseError", pErr)
	}
	if _, ok := pErr.Inner.(*RecursiveIncludeError); !ok {
		t.Fatalf("got %v, expected *RecursiveIncludeError", pErr.Inner)
	}
}

func newIntPtr(i int) *int {
	return &i
}

func dictString(d *Dictionary) string {
	var b bytes.Buffer
	b.WriteString("dictionary.Dictionary\n")

	b.WriteString("\tAttributes:\n")
	for _, attr := range d.Attributes {
		b.WriteString(fmt.Sprintf("\t\t%q %q %q %#v %#v\n", attr.Name, attr.OID, attr.Type, attr.FlagHasTag, attr.FlagEncrypt))
	}

	b.WriteString("\tValues:\n")
	for _, value := range d.Values {
		b.WriteString(fmt.Sprintf("\t\t%q %q %d\n", value.Attribute, value.Name, value.Number))
	}

	b.WriteString("\tVendors:\n")
	for _, vendor := range d.Vendors {
		b.WriteString(fmt.Sprintf("\t\t%q %d\n", vendor.Name, vendor.Number))

		b.WriteString("\t\tAttributes:\n")
		for _, attr := range vendor.Attributes {
			b.WriteString(fmt.Sprintf("\t\t%q %q %q %#v %#v\n", attr.Name, attr.OID, attr.Type, attr.FlagHasTag, attr.FlagEncrypt))
		}

		b.WriteString("\t\tValues:\n")
		for _, value := range vendor.Values {
			b.WriteString(fmt.Sprintf("\t\t%q %q %d\n", value.Attribute, value.Name, value.Number))
		}
	}

	return b.String()
}
