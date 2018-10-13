package dictionarygen

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/printer"
	"go/token"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"layeh.com/radius/dictionary"
)

func TestTestData(t *testing.T) {
	tbl := []struct {
		Name          string
		InitParser    func(*dictionary.Parser)
		InitGenerator func(*Generator)
		Err           string
	}{
		{
			Name: "extended",
		},
		{
			Name: "identical-attributes",
			InitParser: func(p *dictionary.Parser) {
				p.IgnoreIdenticalAttributes = true
			},
		},
		{
			Name: "identifier-collision",
			Err:  "conflicting identifier between First_Name (200) and First-Name (201)",
		},
	}

	for _, tt := range tbl {
		t.Run(tt.Name, func(t *testing.T) {
			dictParser := &dictionary.Parser{
				Opener: &dictionary.FileSystemOpener{},
			}
			if tt.InitParser != nil {
				tt.InitParser(dictParser)
			}

			dictFile := filepath.Join("testdata", tt.Name+".dictionary")
			dict, err := dictParser.ParseFile(dictFile)
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
				if tt.Err != "" {
					if !strings.Contains(err.Error(), tt.Err) {
						t.Fatalf("got generate error %v; expected %v", err, tt.Err)
					}
					return
				}
				t.Fatalf("could not generate dictionary code: %s", err)
			}

			docs, err := generateGoDoc(generatedCode)
			if err != nil {
				t.Fatalf("could not generate docs: %s", err)
			}

			generatedFile := filepath.Join("testdata", tt.Name+".generated")
			if err := ioutil.WriteFile(generatedFile, docs, 0644); err != nil {
				t.Fatalf("could not write generated file: %s", err)
			}

			expectedFile := filepath.Join("testdata", tt.Name+".expected")
			expectedDocs, err := ioutil.ReadFile(expectedFile)
			if err != nil {
				t.Fatalf("could not read expected output: %s", err)
			}

			if !bytes.Equal(docs, expectedDocs) {
				t.Fatal("generated docs do not equal expected")
			}

			os.Remove(generatedFile)
		})
	}
}

func generateGoDoc(source []byte) ([]byte, error) {
	fs := token.NewFileSet()

	f, err := parser.ParseFile(fs, "source.go", source, 0)
	if err != nil {
		return nil, err
	}

	pkg := &ast.Package{
		Name: "test",
		Files: map[string]*ast.File{
			"source.go": f,
		},
	}

	d := doc.New(pkg, "", 0)

	var b bytes.Buffer
	printCfg := printer.Config{
		Indent:   1,
		Tabwidth: 8,
		Mode:     printer.TabIndent,
	}

	fmt.Fprintf(&b, "Constants:\n")
	for _, c := range d.Consts {
		if err := printCfg.Fprint(&b, fs, c.Decl); err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "Functions:\n")
	for _, fn := range d.Funcs {
		fmt.Fprintf(&b, "\t")
		if err := printCfg.Fprint(&b, fs, fn.Decl); err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "\n")
	}

	return b.Bytes(), nil
}
