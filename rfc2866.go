package radius

func init() {
	builtinOnce.Do(initDictionary)
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
}
