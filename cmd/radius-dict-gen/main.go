package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"unicode"

	"layeh.com/radius/dictionary"
)

// from golint
var commonInitialisms = map[string]bool{
	"ACL":   true,
	"API":   true,
	"ASCII": true,
	"CPU":   true,
	"CSS":   true,
	"DNS":   true,
	"EOF":   true,
	"GUID":  true,
	"HTML":  true,
	"HTTP":  true,
	"HTTPS": true,
	"ID":    true,
	"IP":    true,
	"JSON":  true,
	"LHS":   true,
	"QPS":   true,
	"RAM":   true,
	"RHS":   true,
	"RPC":   true,
	"SLA":   true,
	"SMTP":  true,
	"SQL":   true,
	"SSH":   true,
	"TCP":   true,
	"TLS":   true,
	"TTL":   true,
	"UDP":   true,
	"UI":    true,
	"UID":   true,
	"UUID":  true,
	"URI":   true,
	"URL":   true,
	"UTF8":  true,
	"VM":    true,
	"XML":   true,
	"XMPP":  true,
	"XSRF":  true,
	"XSS":   true,
}

func nameToName(name string) string {
	fields := strings.FieldsFunc(name, func(r rune) bool {
		return !unicode.IsNumber(r) && !unicode.IsLetter(r)
	})
	var id bytes.Buffer
	for _, field := range fields {
		fieldUpper := strings.ToUpper(field)
		if commonInitialisms[fieldUpper] {
			id.WriteString(fieldUpper)
		} else {
			id.WriteString(strings.Title(field))
		}
	}
	return id.String()
}

func encValue(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

// Type -> Package
type Refs map[string]string

func (r Refs) Set(v string) error {
	s := strings.Split(v, string(os.PathListSeparator))
	if len(s) != 2 {
		return errors.New("invalid format")
	}
	if _, exists := r[s[0]]; exists {
		return errors.New("type already exists")
	}
	if len(s[0]) == 0 || len(s[1]) == 0 {
		return errors.New("empty type and/or package name")
	}
	r[s[0]] = s[1]
	return nil
}

func (r Refs) String() string {
	var b bytes.Buffer
	b.WriteByte('{')
	first := true
	for typ, pkg := range r {
		if first {
			b.WriteString(", ")
			first = false
		}
		b.WriteString(typ)
		b.WriteRune(os.PathListSeparator)
		b.WriteString(pkg)
	}
	b.WriteByte('}')
	return b.String()
}

type Attribute struct {
	*dictionary.Attribute

	Values []*dictionary.Value
}

func (a *Attribute) RemoveValueNumber(n int) {
	for i, v := range a.Values {
		if v.Number == n {
			a.Values = append(a.Values[:i], a.Values[i+1:]...)
			return
		}
	}
}

type ExternalAttribute struct {
	Name string
	Pkg  string

	Values []*dictionary.Value
}

func (e *ExternalAttribute) RemoveValueNumber(n int) {
	for i, v := range e.Values {
		if v.Number == n {
			e.Values = append(e.Values[:i], e.Values[i+1:]...)
			return
		}
	}
}

type Data struct {
	Package string
	// Dict                     *dictionary.Dictionary
	Attributes         []*Attribute
	ExternalAttributes []*ExternalAttribute
}

func (d *Data) GetAttribute(name string) *Attribute {
	for _, attr := range d.Attributes {
		if attr.Name == name {
			return attr
		}
	}
	return nil
}

func (d *Data) GetExternalAttribute(name string) *ExternalAttribute {
	for _, attr := range d.ExternalAttributes {
		if attr.Name == name {
			return attr
		}
	}
	return nil
}

func main() {
	refs := make(Refs)
	packageName := flag.String("package", "main", "generated package name")
	outputFile := flag.String("output", "-", "output file (\"-\" writes to standard out)")
	flag.Var(&refs, "ref", `external package reference (format: "attribute`+string(os.PathListSeparator)+`package")`)
	flag.Parse()

	data := &Data{
		Package: *packageName,
		// Dict:    new(dictionary.Dictionary),
	}

	parser := dictionary.Parser{
		Opener: &dictionary.FileSystemOpener{},
	}

	dict := new(dictionary.Dictionary)
	for _, filename := range flag.Args() {
		localDict, err := parser.ParseFile(filename)
		if err != nil {
			fmt.Printf("radius-dict-gen: %s\n", err)
			os.Exit(1)
		}

		appendDictionary(dict, localDict)
	}

	for _, attr := range dict.Attributes {
		data.Attributes = append(data.Attributes, &Attribute{
			Attribute: attr,
		})
	}

	for _, value := range dict.Values {
		attr := data.GetAttribute(value.Attribute)
		if attr != nil {
			attr.RemoveValueNumber(value.Number)
			attr.Values = append(attr.Values, value)
			continue
		}

		pkg, hasRef := refs[value.Attribute]
		if !hasRef {
			fmt.Printf("radius-dict-gen: unknown attribute %s\n", value.Attribute)
			os.Exit(1)
		}
		exAttr := data.GetExternalAttribute(value.Attribute)
		if exAttr == nil {
			exAttr = &ExternalAttribute{
				Name: value.Attribute,
				Pkg:  pkg,
			}
			data.ExternalAttributes = append(data.ExternalAttributes, exAttr)
		}
		exAttr.RemoveValueNumber(value.Number)
		exAttr.Values = append(exAttr.Values, value)
	}

	sort.Slice(data.Attributes, func(i, j int) bool {
		a, _ := strconv.Atoi(data.Attributes[i].OID)
		b, _ := strconv.Atoi(data.Attributes[j].OID)
		return a < b
	})

	for _, attr := range data.Attributes {
		sort.Slice(attr.Values, func(i, j int) bool {
			return attr.Values[i].Number < attr.Values[j].Number
		})
	}

	for _, attr := range data.ExternalAttributes {
		sort.Slice(attr.Values, func(i, j int) bool {
			return attr.Values[i].Number < attr.Values[j].Number
		})
	}

	var output io.WriteCloser
	if *outputFile == "-" {
		output = os.Stdout
	} else {
		outFile, err := os.Create(*outputFile)
		if err != nil {
			fmt.Printf("radius-dict-gen: %s\n", err)
			os.Exit(1)
		}
		output = outFile
	}

	var b bytes.Buffer
	if err := tpl.Execute(&b, data); err != nil {
		fmt.Printf("radius-dict-gen: %s\n", err)
		os.Exit(1)
	}

	formatted, err := format.Source(b.Bytes())
	if err != nil {
		output.Write(b.Bytes())
		fmt.Printf("radius-dict-gen: %s\n", err)
		os.Exit(1)
	}

	output.Write(formatted)

	if err := output.Close(); err != nil {
		fmt.Printf("radius-dict-gen: %s\n", err)
		os.Exit(1)
	}
}

func appendDictionary(d1, d2 *dictionary.Dictionary) {
	for _, attr := range d2.Attributes {
		d1.Attributes = append(d1.Attributes, attr)
	}
	for _, value := range d2.Values {
		d1.Values = append(d1.Values, value)
	}
	for _, vendor := range d2.Vendors {
		d1.Vendors = append(d1.Vendors, vendor)
	}
}

var tpl = template.Must(template.New("gen").Funcs(template.FuncMap{
	"ident":    nameToName,
	"encValue": encValue,
}).Parse(`// Generated by radius-dict-gen. DO NOT EDIT.

package {{ .Package }}

import (
	"net"
	"strconv"

	"layeh.com/radius"
	{{ with .ExternalAttributes }}
	{{- range . }}
	{{- if .Values }}
	. "{{ .Pkg }}"
	{{- end }}
	{{- end }}
	{{- end }}
)

var _ = radius.Type(0)
var _ = strconv.Itoa
var _ = net.ParseIP

{{ with .Attributes }}
const ({{ range . }}
	{{ ident .Name}}_Type radius.Type = {{ .OID }}{{ end }}
)
{{ end }}

{{ range .ExternalAttributes }}
{{ $attr := . }}
func init() {{ "{" }}{{ range .Values }}
	{{ ident $attr.Name }}_Strings[{{ ident $attr.Name }}_Value_{{ ident .Name }}] = "{{ .Name }}"{{ end }}
}

const ({{ range .Values }}
	{{ ident $attr.Name }}_Value_{{ ident .Name }} {{ ident $attr.Name }} = {{ .Number }}{{ end }}
)
{{ end }}

{{ with .Attributes }}
{{ range . }}
{{ $attr := . }}
{{ if eq .Type.String "integer" }}
type {{ ident .Name }} uint32

{{ if gt (len $attr.Values) 0 }}
const ({{ range $attr.Values }}
	{{ ident $attr.Name }}_Value_{{ ident .Name }} {{ ident $attr.Name }} = {{ .Number }}{{ end }}
)
{{ end }}

var {{ ident .Name}}_Strings = map[{{ ident .Name}}]string{{ "{" }}{{ range $attr.Values }}
	{{ ident $attr.Name }}_Value_{{ ident .Name }}: "{{ .Name }}",{{ end }}
}

func (a {{ ident .Name }}) String() string {
	if str, ok := {{ ident .Name}}_Strings[a]; ok {
		return str
	}
	return "{{ ident .Name }}(" + strconv.Itoa(int(a)) + ")"
}

func {{ ident .Name }}_Add(p *radius.Packet, value {{ ident .Name }}) {
	a := radius.NewInteger(uint32(value))
	p.Add({{ ident .Name }}_Type, a)
}

func {{ ident .Name }}_Get(p *radius.Packet) (value {{ ident .Name }}) {
	value, _ = {{ ident .Name }}_Lookup(p)
	return
}

func {{ ident .Name }}_Gets(p *radius.Packet) (values []{{ ident .Name }}, err error) {
	var i uint32
	for _, attr := range p.Attributes[{{ ident .Name }}_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, {{ ident .Name }}(i))
	}
	return
}

func {{ ident .Name }}_Lookup(p *radius.Packet) (value {{ ident .Name }}, err error) {
	a, ok  := p.Lookup({{ ident .Name }}_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = {{ ident .Name}}(i)
	return
}

func {{ ident .Name }}_Set(p *radius.Packet, value {{ ident .Name }}) {
	a := radius.NewInteger(uint32(value))
	p.Set({{ ident .Name }}_Type, a)
}

{{ else if or (eq .Type.String "string") (eq .Type.String "octets") }}

func {{ ident .Name }}_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	{{ if eq (encValue .FlagEncrypt) 1 }}
	a, err = radius.NewUserPassword(value, p.Secret, p.Authenticator[:])
	{{ else }}
	a, err = radius.NewBytes(value)
	{{ end }}
	if err != nil {
		return
	}
	p.Add({{ ident .Name }}_Type, a)
	return nil
}

func {{ ident .Name }}_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	{{ if eq (encValue .FlagEncrypt) 1 }}
	a, err = radius.NewUserPassword([]byte(value), p.Secret, p.Authenticator[:])
	{{ else }}
	a, err = radius.NewString(value)
	{{ end }}
	if err != nil {
		return
	}
	p.Add({{ ident .Name }}_Type, a)
	return nil
}

func {{ ident .Name }}_Get(p *radius.Packet) (value []byte) {
	value, _ = {{ ident .Name }}_Lookup(p)
	return
}

func {{ ident .Name }}_GetString(p *radius.Packet) (value string) {
	return string({{ ident .Name }}_Get(p))
}

func {{ ident .Name }}_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[{{ ident .Name }}_Type] {
		{{ if eq (encValue .FlagEncrypt) 1 }}
		i, err = radius.UserPassword(attr, p.Secret, p.Authenticator[:])
		{{ else }}
		i = radius.Bytes(attr)
		{{ end }}
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func {{ ident .Name }}_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[{{ ident .Name }}_Type] {
		{{ if eq (encValue .FlagEncrypt) 1 }}
		var up radius.Attribute
		up, err = radius.UserPassword(attr, p.Secret, p.Authenticator[:])
		if err == nil {
			i = string(up)
		}
		{{ else }}
		i = radius.String(attr)
		{{ end }}
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func {{ ident .Name }}_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok  := p.Lookup({{ ident .Name }}_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	{{ if eq (encValue .FlagEncrypt) 1 }}
	value, err = radius.UserPassword(a, p.Secret, p.Authenticator[:])
	{{ else }}
	value = radius.Bytes(a)
	{{ end }}
	return
}

func {{ ident .Name }}_LookupString(p *radius.Packet) (value string, err error) {
	a, ok  := p.Lookup({{ ident .Name }}_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	{{ if eq (encValue .FlagEncrypt) 1 }}
	var b []byte
	b, err = radius.UserPassword(a, p.Secret, p.Authenticator[:])
	if err == nil {
		value = string(b)
	}
	{{ else }}
	value = radius.String(a)
	{{ end }}
	return
}

func {{ ident .Name }}_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	{{ if eq (encValue .FlagEncrypt) 1 }}
	a, err = radius.NewUserPassword(value, p.Secret, p.Authenticator[:])
	{{ else }}
	a, err = radius.NewBytes(value)
	{{ end }}
	if err != nil {
		return
	}
	p.Set({{ ident .Name }}_Type, a)
	return
}

func {{ ident .Name }}_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	{{ if eq (encValue .FlagEncrypt) 1 }}
	a, err = radius.NewUserPassword([]byte(value), p.Secret, p.Authenticator[:])
	{{ else }}
	a, err = radius.NewString(value)
	{{ end }}
	if err != nil {
		return
	}
	p.Set({{ ident .Name }}_Type, a)
	return
}

{{ else if eq .Type.String "ipaddr" }}

func {{ ident .Name }}_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Add({{ ident .Name }}_Type, a)
	return nil
}

func {{ ident .Name }}_Get(p *radius.Packet) (value net.IP) {
	value, _ = {{ ident .Name }}_Lookup(p)
	return
}

func {{ ident .Name }}_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[{{ ident .Name }}_Type] {
		i, err = radius.IPAddr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func {{ ident .Name }}_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok  := p.Lookup({{ ident .Name }}_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPAddr(a)
	return
}

func {{ ident .Name }}_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Set({{ ident .Name }}_Type, a)
	return
}

{{ else if eq .Type.String "vsa" }}

{{ else }}
// TODO: unimplemented {{ .Name }} (type {{ .Type.String }})
{{ end }}
{{ end }}
{{ end }}
`))
