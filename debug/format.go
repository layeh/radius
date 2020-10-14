package debug

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3162"
	"layeh.com/radius/rfc3576"
	"layeh.com/radius/rfc4849"
)

// Provide a function to format and display data messages for easy debugging during development.
// extension method, which allows you to carry separate formatting functions for specific properties, currently using the Hex format directly.
// Note that the formatting function has resource overhead, it is recommended to have a switch to control it, e.g. if debug { FormatPacket(pkt) }

// Formatting String Properties
var stringFormat = func(src []byte) string {
	return string(src)
}

// Formatting some hard-to-understand properties into Hex
var hexFormat = hex.EncodeToString

// Formatting the Uint32 Property
var uInt32Format = func(src []byte) string {
	return strconv.Itoa(int(binary.BigEndian.Uint32(src)))
}

// Formatting IPv4 Properties
var ipv4Format = func(src []byte) string {
	return net.IPv4(src[0], src[1], src[2], src[3]).String()
}

// Register dictionary properties for quick access to string names.
var radiusTypeMap = map[radius.Type]string{
	rfc2865.UserName_Type:               "UserName",
	rfc2865.UserPassword_Type:           "UserPassword",
	rfc2865.CHAPPassword_Type:           "CHAPPassword",
	rfc2865.NASIPAddress_Type:           "NASIPAddress",
	rfc2865.NASPort_Type:                "NASPort",
	rfc2865.ServiceType_Type:            "ServiceType",
	rfc2865.FramedProtocol_Type:         "FramedProtocol",
	rfc2865.FramedIPAddress_Type:        "FramedIPAddress",
	rfc2865.FramedIPNetmask_Type:        "FramedIPNetmask",
	rfc2865.FramedRouting_Type:          "FramedRouting",
	rfc2865.FilterID_Type:               "FilterID",
	rfc2865.FramedMTU_Type:              "FramedMTU",
	rfc2865.FramedCompression_Type:      "FramedCompression",
	rfc2865.LoginIPHost_Type:            "LoginIPHost",
	rfc2865.LoginService_Type:           "LoginService",
	rfc2865.LoginTCPPort_Type:           "LoginTCPPort",
	rfc2865.ReplyMessage_Type:           "ReplyMessage",
	rfc2865.CallbackNumber_Type:         "CallbackNumber",
	rfc2865.CallbackID_Type:             "CallbackID",
	rfc2865.FramedRoute_Type:            "FramedRoute",
	rfc2865.FramedIPXNetwork_Type:       "FramedIPXNetwork",
	rfc2865.State_Type:                  "State",
	rfc2865.Class_Type:                  "Class",
	rfc2865.VendorSpecific_Type:         "VendorSpecific",
	rfc2865.SessionTimeout_Type:         "SessionTimeout",
	rfc2865.IdleTimeout_Type:            "IdleTimeout",
	rfc2865.TerminationAction_Type:      "TerminationAction",
	rfc2865.CalledStationID_Type:        "CalledStationID",
	rfc2865.CallingStationID_Type:       "CallingStationID",
	rfc2865.NASIdentifier_Type:          "NASIdentifier",
	rfc2865.ProxyState_Type:             "ProxyState",
	rfc2865.LoginLATService_Type:        "LoginLATService",
	rfc2865.LoginLATNode_Type:           "LoginLATNode",
	rfc2865.LoginLATGroup_Type:          "LoginLATGroup",
	rfc2865.FramedAppleTalkLink_Type:    "FramedAppleTalkLink",
	rfc2865.FramedAppleTalkNetwork_Type: "FramedAppleTalkNetwork",
	rfc2865.FramedAppleTalkZone_Type:    "FramedAppleTalkZone",
	rfc2865.CHAPChallenge_Type:          "CHAPChallenge",
	rfc2865.NASPortType_Type:            "NASPortType",
	rfc2865.PortLimit_Type:              "PortLimit",
	rfc2865.LoginLATPort_Type:           "LoginLATPort",
	rfc2866.AcctStatusType_Type:         "AcctStatusType",
	rfc2866.AcctDelayTime_Type:          "AcctDelayTime",
	rfc2866.AcctInputOctets_Type:        "AcctInputOctets",
	rfc2866.AcctOutputOctets_Type:       "AcctOutputOctets",
	rfc2866.AcctSessionID_Type:          "AcctSessionID",
	rfc2866.AcctAuthentic_Type:          "AcctAuthentic",
	rfc2866.AcctSessionTime_Type:        "AcctSessionTime",
	rfc2866.AcctInputPackets_Type:       "AcctInputPackets",
	rfc2866.AcctOutputPackets_Type:      "AcctOutputPackets",
	rfc2866.AcctTerminateCause_Type:     "AcctTerminateCause",
	rfc2866.AcctMultiSessionID_Type:     "AcctMultiSessionID",
	rfc2866.AcctLinkCount_Type:          "AcctLinkCount",
	rfc2869.AcctInputGigawords_Type:     "AcctInputGigawords",
	rfc2869.AcctOutputGigawords_Type:    "AcctOutputGigawords",
	rfc2869.EventTimestamp_Type:         "EventTimestamp",
	rfc2869.ARAPPassword_Type:           "ARAPPassword",
	rfc2869.ARAPFeatures_Type:           "ARAPFeatures",
	rfc2869.ARAPZoneAccess_Type:         "ARAPZoneAccess",
	rfc2869.ARAPSecurity_Type:           "ARAPSecurity",
	rfc2869.ARAPSecurityData_Type:       "ARAPSecurityData",
	rfc2869.PasswordRetry_Type:          "PasswordRetry",
	rfc2869.Prompt_Type:                 "Prompt",
	rfc2869.ConnectInfo_Type:            "ConnectInfo",
	rfc2869.ConfigurationToken_Type:     "ConfigurationToken",
	rfc2869.EAPMessage_Type:             "EAPMessage",
	rfc2869.MessageAuthenticator_Type:   "MessageAuthenticator",
	rfc2869.ARAPChallengeResponse_Type:  "ARAPChallengeResponse",
	rfc2869.AcctInterimInterval_Type:    "AcctInterimInterval",
	rfc2869.NASPortID_Type:              "NASPortID",
	rfc2869.FramedPool_Type:             "FramedPool",
	rfc3162.NASIPv6Address_Type:         "NASIPv6Address",
	rfc3162.FramedInterfaceID_Type:      "FramedInterfaceID",
	rfc3162.FramedIPv6Prefix_Type:       "FramedIPv6Prefix",
	rfc3162.LoginIPv6Host_Type:          "LoginIPv6Host",
	rfc3162.FramedIPv6Route_Type:        "FramedIPv6Route",
	rfc3162.FramedIPv6Pool_Type:         "FramedIPv6Pool",
	rfc3576.ErrorCause_Type:             "ErrorCause",
	rfc4849.NASFilterRule_Type:          "NASFilterRule",
	rfc2868.TunnelType_Type:             "TunnelType",
	rfc2868.TunnelMediumType_Type:       "TunnelMediumType",
	rfc2868.TunnelClientEndpoint_Type:   "TunnelClientEndpoint",
	rfc2868.TunnelServerEndpoint_Type:   "TunnelServerEndpoint",
	rfc2868.TunnelPassword_Type:         "TunnelPassword",
	rfc2868.TunnelPrivateGroupID_Type:   "TunnelPrivateGroupID",
	rfc2868.TunnelAssignmentID_Type:     "TunnelAssignmentID",
	rfc2868.TunnelPreference_Type:       "TunnelPreference",
	rfc2868.TunnelClientAuthID_Type:     "TunnelClientAuthID",
	rfc2868.TunnelServerAuthID_Type:     "TunnelServerAuthID",
}

// Register common formatting functions for quick property formatting.
var radiusTypeFuncMap = map[radius.Type]func(s []byte) string{
	rfc2865.UserName_Type:               stringFormat,
	rfc2865.UserPassword_Type:           hexFormat,
	rfc2865.CHAPPassword_Type:           hexFormat,
	rfc2865.NASIPAddress_Type:           ipv4Format,
	rfc2865.NASPort_Type:                uInt32Format,
	rfc2865.ServiceType_Type:            uInt32Format,
	rfc2865.FramedProtocol_Type:         uInt32Format,
	rfc2865.FramedIPAddress_Type:        ipv4Format,
	rfc2865.FramedIPNetmask_Type:        ipv4Format,
	rfc2865.FramedRouting_Type:          uInt32Format,
	rfc2865.FilterID_Type:               stringFormat,
	rfc2865.FramedMTU_Type:              uInt32Format,
	rfc2865.FramedCompression_Type:      uInt32Format,
	rfc2865.LoginIPHost_Type:            ipv4Format,
	rfc2865.LoginService_Type:           uInt32Format,
	rfc2865.LoginTCPPort_Type:           uInt32Format,
	rfc2865.ReplyMessage_Type:           stringFormat,
	rfc2865.CallbackNumber_Type:         stringFormat,
	rfc2865.CallbackID_Type:             stringFormat,
	rfc2865.FramedRoute_Type:            stringFormat,
	rfc2865.FramedIPXNetwork_Type:       ipv4Format,
	rfc2865.State_Type:                  stringFormat,
	rfc2865.Class_Type:                  stringFormat,
	rfc2865.VendorSpecific_Type:         hexFormat,
	rfc2865.SessionTimeout_Type:         uInt32Format,
	rfc2865.IdleTimeout_Type:            uInt32Format,
	rfc2865.TerminationAction_Type:      uInt32Format,
	rfc2865.CalledStationID_Type:        stringFormat,
	rfc2865.CallingStationID_Type:       stringFormat,
	rfc2865.NASIdentifier_Type:          stringFormat,
	rfc2865.ProxyState_Type:             stringFormat,
	rfc2865.LoginLATService_Type:        hexFormat,
	rfc2865.LoginLATNode_Type:           hexFormat,
	rfc2865.LoginLATGroup_Type:          hexFormat,
	rfc2865.FramedAppleTalkLink_Type:    hexFormat,
	rfc2865.FramedAppleTalkNetwork_Type: hexFormat,
	rfc2865.FramedAppleTalkZone_Type:    hexFormat,
	rfc2865.CHAPChallenge_Type:          hexFormat,
	rfc2865.NASPortType_Type:            uInt32Format,
	rfc2865.PortLimit_Type:              hexFormat,
	rfc2865.LoginLATPort_Type:           hexFormat,
	rfc2866.AcctStatusType_Type:         uInt32Format,
	rfc2866.AcctDelayTime_Type:          uInt32Format,
	rfc2866.AcctInputOctets_Type:        uInt32Format,
	rfc2866.AcctOutputOctets_Type:       uInt32Format,
	rfc2866.AcctSessionID_Type:          stringFormat,
	rfc2866.AcctAuthentic_Type:          uInt32Format,
	rfc2866.AcctSessionTime_Type:        uInt32Format,
	rfc2866.AcctInputPackets_Type:       uInt32Format,
	rfc2866.AcctOutputPackets_Type:      uInt32Format,
	rfc2866.AcctTerminateCause_Type:     uInt32Format,
	rfc2866.AcctMultiSessionID_Type:     stringFormat,
	rfc2866.AcctLinkCount_Type:          uInt32Format,
	rfc2869.AcctInputGigawords_Type:     uInt32Format,
	rfc2869.AcctOutputGigawords_Type:    uInt32Format,
	rfc2869.EventTimestamp_Type:         uInt32Format,
	rfc2869.ARAPPassword_Type:           hexFormat,
	rfc2869.ARAPFeatures_Type:           hexFormat,
	rfc2869.ARAPZoneAccess_Type:         hexFormat,
	rfc2869.ARAPSecurity_Type:           hexFormat,
	rfc2869.ARAPSecurityData_Type:       hexFormat,
	rfc2869.PasswordRetry_Type:          hexFormat,
	rfc2869.Prompt_Type:                 hexFormat,
	rfc2869.ConnectInfo_Type:            stringFormat,
	rfc2869.ConfigurationToken_Type:     stringFormat,
	rfc2869.EAPMessage_Type:             stringFormat,
	rfc2869.MessageAuthenticator_Type:   stringFormat,
	rfc2869.ARAPChallengeResponse_Type:  hexFormat,
	rfc2869.AcctInterimInterval_Type:    uInt32Format,
	rfc2869.NASPortID_Type:              stringFormat,
	rfc2869.FramedPool_Type:             stringFormat,
	rfc3162.NASIPv6Address_Type:         hexFormat,
	rfc3162.FramedInterfaceID_Type:      hexFormat,
	rfc3162.FramedIPv6Prefix_Type:       hexFormat,
	rfc3162.LoginIPv6Host_Type:          hexFormat,
	rfc3162.FramedIPv6Route_Type:        hexFormat,
	rfc3162.FramedIPv6Pool_Type:         hexFormat,
	rfc3576.ErrorCause_Type:             uInt32Format,
	rfc4849.NASFilterRule_Type:          stringFormat,
	rfc2868.TunnelType_Type:             uInt32Format,
	rfc2868.TunnelMediumType_Type:       uInt32Format,
	rfc2868.TunnelClientEndpoint_Type:   stringFormat,
	rfc2868.TunnelServerEndpoint_Type:   stringFormat,
	rfc2868.TunnelPassword_Type:         stringFormat,
	rfc2868.TunnelPrivateGroupID_Type:   stringFormat,
	rfc2868.TunnelAssignmentID_Type:     hexFormat,
	rfc2868.TunnelPreference_Type:       hexFormat,
	rfc2868.TunnelClientAuthID_Type:     hexFormat,
	rfc2868.TunnelServerAuthID_Type:     hexFormat,
}

// Formatting Type
func formatType(t radius.Type) string {
	v, ok := radiusTypeMap[t]
	if !ok {
		return strconv.Itoa(int(t))
	}
	return v
}

// Formatting Properties
func formatAttribute(avp *radius.AVP) string {
	vfunc, ok := radiusTypeFuncMap[avp.Type]
	if !ok {
		return hexFormat(avp.Attribute)
	}
	return vfunc(avp.Attribute)
}

// Formatting radius packet, e.g.
//
/*
	RADIUS Packet:
		Identifier: 102
        Code: 1
        Authenticator:b1a275222be6b9f7e21585e11bd6d396
        Attributes:
            UserName: test
            UserPassword: dcff9f2a6fc7673ed5d58221a7aedaf0
            NASIdentifier: tradtest
            NASIPAddress: 10.10.10.10
            NASPort: 0
            NASPortType: 0
            NASPortID: slot=2;subslot=2;port=22;vlanid=100;
            CalledStationID: 11:11:11:11:11:11
            CallingStationID: 11:11:11:11:11:11
            VendorSpecific(14988,9): 4d696b726f74696b
*/
func FormatPacket(p *radius.Packet) string {
	var buff = new(strings.Builder)
	buff.WriteString("RADIUS Packet: \n")
	buff.WriteString("\tIdentifier: ")
	buff.WriteString(strconv.Itoa(int(p.Identifier)))
	buff.WriteByte('\n')
	buff.WriteString("\tCode: ")
	buff.WriteString(strconv.Itoa(int(p.Code)))
	buff.WriteByte('\n')
	buff.WriteString("\tAuthenticator:")
	buff.WriteString(hexFormat(p.Authenticator[:]))
	buff.WriteByte('\n')
	buff.WriteString("\tAttributes:\n")
	for _, attribute := range p.Attributes {
		if attribute.Type != rfc2865.VendorSpecific_Type {
			buff.WriteByte('\t')
			buff.WriteByte('\t')
			buff.WriteString(formatType(attribute.Type))
			buff.WriteString(": ")
			buff.WriteString(formatAttribute(attribute))
			buff.WriteByte('\n')
		} else {
			buff.WriteByte('\t')
			buff.WriteByte('\t')
			buff.WriteString(formatType(attribute.Type))
			buff.WriteByte('(')
			buff.WriteString(strconv.FormatUint(uint64(binary.BigEndian.Uint16(attribute.Attribute[2:4])), 10))
			buff.WriteByte(',')
			buff.WriteString(strconv.Itoa(int(attribute.Attribute[4:5][0])))
			buff.WriteString("): ")
			buff.WriteString(hexFormat(attribute.Attribute[6:]))
		}
	}
	return buff.String()
}
