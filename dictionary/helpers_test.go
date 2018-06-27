package dictionary

import (
	"reflect"
	"testing"
)

func TestMerge(t *testing.T) {
	files := []MemoryFile{
		{
			Filename: "dict1",
			Contents: `
VENDOR Test 32473
BEGIN-VENDOR Test
ATTRIBUTE Test-Vendor-Name 5 string
END-VENDOR Test`,
		},
		{
			Filename: "dict2",
			Contents: `
VENDOR Test 32473
BEGIN-VENDOR Test
ATTRIBUTE Test-Vendor-Int 10 integer
END-VENDOR Test`,
		},
	}

	parser := &Parser{
		Opener: MemoryOpener(files),
	}
	d1, err := parser.ParseFile("dict1")
	if err != nil {
		t.Fatal(err)
	}

	d2, err := parser.ParseFile("dict2")
	if err != nil {
		t.Fatal(err)
	}

	merged, err := Merge(d1, d2)
	if err != nil {
		t.Fatal(err)
	}

	expected := &Dictionary{
		Vendors: []*Vendor{
			{
				Name:   "Test",
				Number: 32473,
				Attributes: []*Attribute{
					{
						Name: "Test-Vendor-Name",
						Type: AttributeString,
						OID:  OID{5},
					},
					{
						Name: "Test-Vendor-Int",
						Type: AttributeInteger,
						OID:  OID{10},
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(merged, expected) {
		t.Fatalf("got:\n%#v\nexpected:\n%#v", merged, expected)
	}
}
