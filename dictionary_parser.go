package radius

import (
	"os"
	"bufio"
	"regexp"
	"strconv"
	"strings"
)

type dictionaryAttribute struct {
	Name   string
	Format string
}

type dictionaryVendor struct {
	ID   uint32
	Name string
	Attributes [256]*dictionaryAttribute
}

type dictionaryRegexp struct {
	reVendor       *regexp.Regexp
	reAttribute    *regexp.Regexp
	namesVendor    []string
	namesAttribute []string
}

type DictionaryParser struct {
	Vendors      map[uint32]*dictionaryVendor
	parserRegexp *dictionaryRegexp
}

func (dr *dictionaryRegexp) init() {
	patternVendor := `VENDOR\s*(?P<VendorName>[[:alnum:]]*)\s*` +
	                 `(?P<VendorID>[[:digit:]]*)`
	patternAttr   := `ATTRIBUTE\s*(?P<AttrName>[a-zA-Z0-9\-\_]*)\s*` +
	                 `(?P<AttrID>[[:digit:]]*)\s*` +
	                 `(?P<AttrFormat>[[:alnum:]]*\s*)`

	dr.reVendor = regexp.MustCompile(patternVendor)
	dr.reAttribute = regexp.MustCompile(patternAttr)
	dr.namesVendor = dr.reVendor.SubexpNames()
	dr.namesAttribute = dr.reAttribute.SubexpNames()
}

func (dr *dictionaryRegexp) lineParse(line string) (rtype int, result map[string]string) {
	var names []string
	var r []string

	rtype = 0

	if dr.reAttribute.MatchString(line) {
		r = dr.reAttribute.FindAllStringSubmatch(line, -1)[0]
		rtype = 2
		names = dr.namesAttribute
	} else if dr.reVendor.MatchString(line) {
		r = dr.reVendor.FindAllStringSubmatch(line, -1)[0]
		rtype = 1
		names = dr.namesVendor
	}

	if rtype > 0 {
		result = map[string]string{}
		for i, val := range r {
			result[names[i]] = val
		}
	}

	return
}

func (dp *DictionaryParser) Parse(f string) {
	if dp.parserRegexp == nil {
		dp.parserRegexp = &dictionaryRegexp{}
		dp.parserRegexp.init()
	}

	if dp.Vendors == nil {
		dp.Vendors = make(map[uint32]*dictionaryVendor)
	}

	handle, _ := os.Open(f)
	defer handle.Close()

	vid := uint32(0)

	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		rtype, result := dp.parserRegexp.lineParse(scanner.Text())
		switch rtype {
			case 1:
			cvid, err := strconv.Atoi(result["VendorID"])
			if err == nil {
				vid = uint32(cvid)
				if dp.Vendors[vid] == nil {
					dp.Vendors[vid] = &dictionaryVendor{}
				}

				dp.Vendors[vid].ID = vid
			}
			case 2:
			caid, err := strconv.Atoi(result["AttrID"])
			if err == nil && vid != 0 {
				aid := byte(caid)

				if dp.Vendors[vid].Attributes[aid] == nil {
					dp.Vendors[vid].Attributes[aid] = &dictionaryAttribute{}
				}

				dp.Vendors[vid].Attributes[aid].Name =
					strings.TrimSpace(result["AttrName"])
				dp.Vendors[vid].Attributes[aid].Format =
					strings.TrimSpace(result["AttrFormat"])
			}
		}
	}
}
