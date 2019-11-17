package rfc3079

import (
	"reflect"
	"testing"
)

func TestGetMasterKey(t *testing.T) {
	type args struct {
		passwordHashHash []byte
		ntResponse       []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "rfc3079, 3.5.1",
			args: args{
				passwordHashHash: []byte{
					0x41, 0xC0, 0x0C, 0x58, 0x4B, 0xD2, 0xD9, 0x1C, 0x40, 0x17, 0xA2, 0xA1, 0x2F, 0xA5, 0x9F, 0x3F,
				},
				ntResponse: []byte{
					0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E, 0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54, 0x42, 0x33,
					0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF,
				},
			},
			want: []byte{
				0xFD, 0xEC, 0xE3, 0x71, 0x7A, 0x8C, 0x83, 0x8C, 0xB3, 0x88, 0xE5, 0x27, 0xAE, 0x3C, 0xDD, 0x31,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetMasterKey(tt.args.passwordHashHash, tt.args.ntResponse); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetMasterKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAsymmetricStartKey(t *testing.T) {
	type args struct {
		masterKey        []byte
		sessionKeyLength KeyLength
		isSend           bool
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "40-bit, rfc3079, 3.5.1",
			args: args{
				masterKey: []byte{
					0xFD, 0xEC, 0xE3, 0x71, 0x7A, 0x8C, 0x83, 0x8C, 0xB3, 0x88, 0xE5, 0x27, 0xAE, 0x3C, 0xDD, 0x31,
				},
				sessionKeyLength: KeyLength40Bit,
				isSend:           true,
			},
			want: []byte{
				0x8B, 0x7C, 0xDC, 0x14, 0x9B, 0x99, 0x3A, 0x1B,
			},
		},
		{
			name: "128-bit, rfc3079, 3.5.3",
			args: args{
				masterKey: []byte{
					0xFD, 0xEC, 0xE3, 0x71, 0x7A, 0x8C, 0x83, 0x8C, 0xB3, 0x88, 0xE5, 0x27, 0xAE, 0x3C, 0xDD, 0x31,
				},
				sessionKeyLength: 16,
				isSend:           true,
			},
			want: []byte{
				0x8B, 0x7C, 0xDC, 0x14, 0x9B, 0x99, 0x3A, 0x1B, 0xA1, 0x18, 0xCB, 0x15, 0x3F, 0x56, 0xDC, 0xCB,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAsymmetricStartKey(tt.args.masterKey, tt.args.sessionKeyLength, tt.args.isSend)
			if err != nil {
				t.Errorf("err = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAsymmetricStartKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
