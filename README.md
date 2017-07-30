# radius [![GoDoc](https://godoc.org/layeh.com/radius?status.svg)](https://godoc.org/layeh.com/radius)

a Go (golang) [RADIUS](https://tools.ietf.org/html/rfc2865) client and server implementation

## Installation

    go get -u layeh.com/radius

## RADIUS Dictionaries

Included in this package is the command line program `radius-dict-gen` It can be installed with:

    go get -u layeh.com/radius/radius-dict-gen

This program will generate helper functions and types for reading and manipulating RADIUS attributes in a packet. It is recommended that you generate code for any RADIUS dictionary you are interested in consuming.

Included in this repository are sub-packages of helpers for commonly used RADIUS attributes, including `rfc2865` and `rfc2866`.

## License

MPL 2.0
