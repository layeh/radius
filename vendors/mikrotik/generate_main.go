//+build ignore

package main

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/net/html"
	"layeh.com/radius/dictionary"
	"layeh.com/radius/dictionarygen"
)

const (
	Init = iota
	FoundPre
	Discarding
)

func main() {
	resp, err := http.Get(`https://wiki.mikrotik.com/wiki/Manual:RADIUS_Client/vendor_dictionary`)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// the dictionary is inside a <pre> tag, so... tokenize it out
	var extractedBody bytes.Buffer
	var state int

	tokenizer := html.NewTokenizer(resp.Body)
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			err := tokenizer.Err()
			if err == io.EOF {
				break
			} else {
				log.Fatal(err)
			}
		}

		switch state {
		case Init:
			if tokenType == html.StartTagToken {
				token := tokenizer.Token()
				if token.Data == "pre" {
					state = FoundPre
				}
			}

		case FoundPre:
			if tokenType == html.TextToken {
				extractedBody.WriteString(tokenizer.Token().Data)
			} else {
				state = Discarding
			}
		}
	}

	parser := dictionary.Parser{
		Opener: restrictedOpener{
			"main.dictionary": extractedBody.Bytes(),
		},
	}
	dict, err := parser.ParseFile("main.dictionary")
	if err != nil {
		log.Fatal(err)
	}

	if len(dict.Vendors) != 1 || dict.Vendors[0].Number != 14988 {
		log.Fatal("expected dictionary to contain vendor 14988")
	}

	gen := dictionarygen.Generator{
		Package: "mikrotik",
	}
	generated, err := gen.Generate(dict)
	if err != nil {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile("generated.go", generated, 0644); err != nil {
		log.Fatal(err)
	}
}

type restrictedOpener map[string][]byte

func (r restrictedOpener) OpenFile(name string) (dictionary.File, error) {
	contents, ok := r[name]
	if !ok {
		return nil, errors.New("unknown file " + name)
	}
	return &restrictedFile{
		Reader:    bytes.NewReader(contents),
		NameValue: name,
	}, nil
}

type restrictedFile struct {
	io.Reader
	NameValue string
}

func (r *restrictedFile) Name() string {
	return r.NameValue
}

func (r *restrictedFile) Close() error {
	return nil
}
