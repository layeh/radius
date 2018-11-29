//+build ignore

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"

	"layeh.com/radius/dictionary"
	"layeh.com/radius/dictionarygen"
)

type ParseResponse struct {
	Text map[string]string `json:"text"`
}

type APIResponse struct {
	Parse *ParseResponse `json:"parse"`
}

var dictRe = regexp.MustCompile(`(?ms)^<pre>$(.*)^</pre>$`)

func main() {
	resp, err := http.Get(`https://wiki.mikrotik.com/api.php?page=Manual:RADIUS_Client/vendor_dictionary&action=parse&format=json`)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var apiResponse APIResponse
	if err := decoder.Decode(&apiResponse); err != nil {
		log.Fatal(err)
	}

	pageContents := apiResponse.Parse.Text["*"]
	dictContents := dictRe.FindStringSubmatch(pageContents)[1]

	parser := dictionary.Parser{
		Opener: restrictedOpener{
			"main.dictionary": []byte(dictContents),
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
