package debug

import (
	"net"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/vendors/mikrotik"
)

func getPacket() *radius.Packet {
	pkt := radius.New(radius.CodeAccessRequest, []byte("123456"))
	rfc2865.UserName_SetString(pkt, "test")
	rfc2865.UserPassword_SetString(pkt, "test")
	rfc2865.NASIdentifier_Set(pkt, []byte("tradtest"))
	rfc2865.NASIPAddress_Set(pkt, net.ParseIP("10.10.10.10"))
	rfc2865.NASPort_Set(pkt, 0)
	rfc2865.NASPortType_Set(pkt, 0)
	rfc2869.NASPortID_Set(pkt, []byte("slot=2;subslot=2;port=22;vlanid=100;"))
	rfc2865.CalledStationID_SetString(pkt, "11:11:11:11:11:11")
	rfc2865.CallingStationID_SetString(pkt, "11:11:11:11:11:11")
	mikrotik.MikrotikRealm_SetString(pkt, "Mikrotik")
	return pkt
}

func TestFormatPacket(t *testing.T) {
	t.Log(FormatPacket(getPacket()))
}

func BenchmarkFormatPacket(b *testing.B) {
	var pkt = getPacket()
	for i := 0; i < b.N; i++ {
		FormatPacket(pkt)
	}
}
