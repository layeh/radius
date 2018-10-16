package dictionary

import (
	"reflect"
	"testing"
)

func TestMerge(t *testing.T) {
	parser := &Parser{
		Opener: &FileSystemOpener{
			Root: "testdata",
		},
	}
	d1, err := parser.ParseFile("merge_1.dictionary")
	if err != nil {
		t.Fatal(err)
	}

	d2, err := parser.ParseFile("merge_2.dictionary")
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
