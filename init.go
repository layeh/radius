package radius // import "layeh.com/radius"

func init() {
	Builtin = &Dictionary{}

	AttributeText = attributeText{}
	AttributeString = attributeString{}
	AttributeAddress = attributeAddress{}
	AttributeInteger = attributeInteger{}
	AttributeTime = attributeTime{}
	AttributeUnknown = attributeString{}

	// RFC 2865
	Builtin.MustRegister("User-Name", 1, AttributeText)
	Builtin.MustRegister("User-Password", 2, rfc2865UserPassword{})
	Builtin.MustRegister("CHAP-Password", 3, rfc2865ChapPassword{})
	Builtin.MustRegister("NAS-IP-Address", 4, AttributeAddress)
	Builtin.MustRegister("NAS-Port", 5, AttributeInteger)
	Builtin.MustRegister("Service-Type", 6, AttributeInteger)
	Builtin.MustRegister("Framed-Protocol", 7, AttributeInteger)
	Builtin.MustRegister("Framed-IP-Address", 8, AttributeAddress)
	Builtin.MustRegister("Framed-IP-Netmask", 9, AttributeAddress)
	Builtin.MustRegister("Framed-Routing", 10, AttributeInteger)
	Builtin.MustRegister("Filter-Id", 11, AttributeText)
	Builtin.MustRegister("Framed-MTU", 12, AttributeInteger)
	Builtin.MustRegister("Framed-Compression", 13, AttributeInteger)
	Builtin.MustRegister("Login-IP-Host", 14, AttributeAddress)
	Builtin.MustRegister("Login-Service", 15, AttributeInteger)
	Builtin.MustRegister("Login-TCP-Port", 16, AttributeInteger)
	Builtin.MustRegister("Reply-Message", 18, AttributeText)
	Builtin.MustRegister("Callback-Number", 19, AttributeString)
	Builtin.MustRegister("Callback-Id", 20, AttributeString)
	Builtin.MustRegister("Framed-Route", 22, AttributeText)
	Builtin.MustRegister("Framed-IPX-Network", 23, AttributeAddress)
	Builtin.MustRegister("State", 24, AttributeString)
	Builtin.MustRegister("Class", 25, AttributeString)
	Builtin.MustRegister("Vendor-Specific", 26, rfc2865VendorSpecific{})
	Builtin.MustRegister("Session-Timeout", 27, AttributeInteger)
	Builtin.MustRegister("Idle-Timeout", 28, AttributeInteger)
	Builtin.MustRegister("Termination-Action", 29, AttributeInteger)
	Builtin.MustRegister("Called-Station-Id", 30, AttributeString)
	Builtin.MustRegister("Calling-Station-Id", 31, AttributeString)
	Builtin.MustRegister("NAS-Identifier", 32, AttributeString)
	Builtin.MustRegister("Proxy-State", 33, AttributeString)
	Builtin.MustRegister("Login-LAT-Service", 34, AttributeString)
	Builtin.MustRegister("Login-LAT-Node", 35, AttributeString)
	Builtin.MustRegister("Login-LAT-Group", 36, AttributeString)
	Builtin.MustRegister("Framed-AppleTalk-Link", 37, AttributeInteger)
	Builtin.MustRegister("Framed-AppleTalk-Network", 38, AttributeInteger)
	Builtin.MustRegister("Framed-AppleTalk-Zone", 39, AttributeString)
	Builtin.MustRegister("CHAP-Challenge", 60, AttributeString)
	Builtin.MustRegister("NAS-Port-Type", 61, AttributeInteger)
	Builtin.MustRegister("Port-Limit", 62, AttributeInteger)
	Builtin.MustRegister("Login-LAT-Port", 63, AttributeString)

	// RFC 2866
	Builtin.MustRegister("Acct-Status-Type", 40, AttributeInteger)
	Builtin.MustRegister("Acct-Delay-Time", 41, AttributeInteger)
	Builtin.MustRegister("Acct-Input-Octets", 42, AttributeInteger)
	Builtin.MustRegister("Acct-Output-Octets", 43, AttributeInteger)
	Builtin.MustRegister("Acct-Session-Id", 44, AttributeText)
	Builtin.MustRegister("Acct-Authentic", 45, AttributeInteger)
	Builtin.MustRegister("Acct-Session-Time", 46, AttributeInteger)
	Builtin.MustRegister("Acct-Input-Packets", 47, AttributeInteger)
	Builtin.MustRegister("Acct-Output-Packets", 48, AttributeInteger)
	Builtin.MustRegister("Acct-Terminate-Cause", 49, AttributeInteger)
	Builtin.MustRegister("Acct-Multi-Session-Id", 50, AttributeText)
	Builtin.MustRegister("Acct-Link-Count", 51, AttributeInteger)

	//RFC 2869 (not full, see https://www.ietf.org/rfc/rfc2869.txt)
	Builtin.MustRegister("Acct-Input-Gigawords", 52, AttributeInteger)
	Builtin.MustRegister("Acct-Output-Gigawords", 53, AttributeInteger)
	Builtin.MustRegister("NAS-Port-ID", 87, AttributeString)
}
