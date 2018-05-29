package dictionarygen

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"layeh.com/radius/dictionary"
)

func TestTestData(t *testing.T) {
	tbl := []struct {
		Name          string
		InitParser    func(*dictionary.Parser)
		InitGenerator func(*Generator)
	}{
		{
			Name: "identical-attributes",
			InitParser: func(p *dictionary.Parser) {
				p.IgnoreIdenticalAttributes = true
			},
		},
	}

	for _, tt := range tbl {
		t.Run(tt.Name, func(t *testing.T) {
			parser := &dictionary.Parser{
				Opener: &dictionary.FileSystemOpener{},
			}
			if tt.InitParser != nil {
				tt.InitParser(parser)
			}

			dictFile := filepath.Join("testdata", tt.Name+".dictionary")
			dict, err := parser.ParseFile(dictFile)
			if err != nil {
				t.Fatalf("could not parse file: %s", err)
			}

			generator := &Generator{
				Package: "main",
			}
			if tt.InitGenerator != nil {
				tt.InitGenerator(generator)
			}

			generatedCode, err := generator.Generate(dict)
			if err != nil {
				t.Fatalf("could not generate dictionary code: %s", err)
			}

			generatedFile := filepath.Join("testdata", tt.Name+".generated")
			if err := ioutil.WriteFile(generatedFile, generatedCode, 0644); err != nil {
				t.Fatalf("could not write generated file: %s", err)
			}

			expectedFile := filepath.Join("testdata", tt.Name+".expected")
			expectedCode, err := ioutil.ReadFile(expectedFile)
			if err != nil {
				t.Fatalf("could not read expected output: %s", err)
			}

			if !bytes.Equal(generatedCode, expectedCode) {
				t.Fatal("generated code does not equal expected")
			}

			os.Remove(generatedFile)
		})
	}
}
