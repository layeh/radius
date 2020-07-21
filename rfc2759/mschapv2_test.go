package rfc2759

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func Test_parityPadDESKey(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		wantOut []byte
	}{
		{
			name:    "a",
			in:      []byte{0x61, 0xee, 0x8b, 0x50, 0x74, 0x8f, 0x5e},
			wantOut: []byte{0x61, 0xf7, 0xa2, 0x6b, 0x07, 0xa4, 0x3d, 0xbc},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotOut := parityPadDESKey(tt.in); !bytes.Equal(gotOut, tt.wantOut) {
				t.Errorf("parityPadKey() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}

func TestGenerateNTResponse(t *testing.T) {
	type args struct {
		authenticatorChallenge []byte
		peerChallenge          []byte
		username               []byte
		password               []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "1",
			args: args{
				authenticatorChallenge: []byte{
					0x77, 0xac, 0x2d, 0x4c, 0x31, 0x2a, 0x6a, 0xfe, 0xb9, 0xd1, 0x76, 0xb4, 0xdd, 0x1d, 0x1a, 0x1d,
				},
				peerChallenge: []byte{
					0x34, 0x13, 0x16, 0x83, 0x81, 0xf7, 0x4b, 0x7b, 0x28, 0xe6, 0x08, 0x8b, 0xd7, 0xa5, 0x0d, 0xe9,
				},
				username: []byte("test"),
				password: []byte("superSecretPassword"),
			},
			want: []byte{
				0x62, 0x95, 0xb2, 0x14, 0x39, 0x95, 0xf9, 0xf6, 0x58, 0x69, 0x19, 0x77, 0xef, 0x12, 0x79, 0x89, 0x10, 0xff, 0x29, 0x73, 0xb5, 0xb5, 0x13, 0xba,
			},
		},
		{
			name: "2",
			args: args{
				authenticatorChallenge: []byte{
					0xd5, 0x71, 0x7d, 0x58, 0xe9, 0xfb, 0x9c, 0xf4, 0x2d, 0xbb, 0x0c, 0x1a, 0x8a, 0xdf, 0x98, 0x79,
				},
				peerChallenge: []byte{
					0x27, 0x9c, 0xb4, 0x11, 0x49, 0x4d, 0x5a, 0x84, 0xcd, 0xf2, 0xd2, 0xee, 0x36, 0xfb, 0x5c, 0xdd,
				},
				username: []byte("test"),
				password: []byte("superSecretPassword"),
			},
			want: []byte{
				0xf5, 0xe4, 0x71, 0xec, 0xb5, 0x59, 0xa9, 0xf7, 0xc6, 0x9a, 0x70, 0x8b, 0x12, 0xe7, 0xa8, 0x6d, 0xd2, 0xfe, 0xf9, 0xab, 0x3f, 0x2a, 0xed, 0x0a,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateNTResponse(tt.args.authenticatorChallenge, tt.args.peerChallenge, tt.args.username, tt.args.password)
			if err != nil {
				t.Errorf("err = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("GenerateNTResponse() got %s, wanted %s", hex.EncodeToString(got), hex.EncodeToString(tt.want))
			}
		})
	}
}

func TestGenerateAuthenticatorResponse(t *testing.T) {
	type args struct {
		authenticatorChallenge []byte
		peerChallenge          []byte
		ntResponse             []byte
		username               []byte
		password               []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "2",
			args: args{
				authenticatorChallenge: []byte{
					0xd5, 0x71, 0x7d, 0x58, 0xe9, 0xfb, 0x9c, 0xf4, 0x2d, 0xbb, 0x0c, 0x1a, 0x8a, 0xdf, 0x98, 0x79,
				},
				peerChallenge: []byte{
					0x27, 0x9c, 0xb4, 0x11, 0x49, 0x4d, 0x5a, 0x84, 0xcd, 0xf2, 0xd2, 0xee, 0x36, 0xfb, 0x5c, 0xdd,
				},
				ntResponse: []byte{
					0xe6, 0xad, 0x73, 0xb3, 0x73, 0x88, 0x39, 0xcc, 0xcf, 0xc0, 0xfb, 0xf3, 0x45, 0x9a, 0x5b, 0x26, 0xac, 0x4b, 0x15, 0x9e, 0xfa, 0xb6, 0xb0, 0x3f,
				},
				username: []byte("test"),
				password: []byte("superSecretPassword"),
			},
			want: "S=E776FC79AC79DED99AEFF66893C920EB34F63396",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateAuthenticatorResponse(tt.args.authenticatorChallenge, tt.args.peerChallenge, tt.args.ntResponse, tt.args.username, tt.args.password)
			if err != nil {
				t.Errorf("err = %v", err)
			}
			if got != tt.want {
				t.Errorf("GenerateAuthenticatorResponse() got %s, want %s", got, tt.want)
			}
		})
	}
}
