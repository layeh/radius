package dictionary

import (
	"sort"
)

func SortAttributes(attrs []*Attribute) {
	sort.Stable(sortAttributes(attrs))
}

type sortAttributes []*Attribute

func (s sortAttributes) Len() int { return len(s) }

func (s sortAttributes) Less(i, j int) bool {
	a := s[i].OID
	b := s[i].OID

	for len(a) > 0 || len(b) > 0 {
		var x, y int
		if len(a) > 0 {
			x = a[0]
			a = a[1:]
		}
		if len(b) > 0 {
			y = b[0]
			b = b[1:]
		}
		if x != y {
			return x < y
		}
	}

	return false
}

func (s sortAttributes) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func SortValues(values []*Value) {
	sort.Stable(sortValues(values))
}

type sortValues []*Value

func (s sortValues) Len() int           { return len(s) }
func (s sortValues) Less(i, j int) bool { return s[i].Number < s[j].Number }
func (s sortValues) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func SortVendors(vendors []*Vendor) {
	sort.Stable(sortVendors(vendors))
}

type sortVendors []*Vendor

func (s sortVendors) Len() int           { return len(s) }
func (s sortVendors) Less(i, j int) bool { return s[i].Number < s[j].Number }
func (s sortVendors) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
