// +build ignore

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"layeh.com/radius/dictionary"
)

func main() {
	outputFile := flag.String("o", "-", "Output filename")
	flag.Parse()

	parser := &dictionary.Parser{
		Opener: &dictionary.FileSystemOpener{},
	}

	dict := &dictionary.Dictionary{}

	for _, filename := range flag.Args() {
		nextDict, err := parser.ParseFile(filename)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		if err := MergeDict(dict, nextDict); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	var w io.Writer
	if *outputFile == "-" {
		w = os.Stdout
	} else {
		f, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	fmt.Fprintln(w, "// Generated file. DO NOT EDIT.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "package debug")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, `import "layeh.com/radius/dictionary"`)
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "var IncludedDictionary = %#v\n", dict)
}

func MergeDict(d1, d2 *dictionary.Dictionary) error {
	// TODO: vendor merging

	// Duplicate checks
	for _, attr := range d2.Attributes {
		existingAttr := d1.AttributeByName(attr.Name)
		if existingAttr == nil {
			existingAttr = d1.AttributeByOID(attr.OID)
		}

		if existingAttr != nil {
			return fmt.Errorf("duplicate attribute %s (%s)", attr.Name, attr.OID)
		}
	}

	// Merge
	d1.Attributes = append(d1.Attributes, d2.Attributes...)
	d1.Values = append(d1.Values, d2.Values...)

	return nil
}
