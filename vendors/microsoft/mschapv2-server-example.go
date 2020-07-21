//+build ignore

package main

import (
	"bytes"
	"log"

	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3079"
	"layeh.com/radius/vendors/microsoft"
)

const (
	radiusSecret = "secret"
)

func main() {
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		username := rfc2865.UserName_Get(r.Packet)
		challenge := microsoft.MSCHAPChallenge_Get(r.Packet)
		response := microsoft.MSCHAP2Response_Get(r.Packet)

		// TODO: look up user in local database.
		// The password must be stored in the clear for CHAP mechanisms to work.
		// In theory, it would be possible to use a password hashed with MD4 as
		// all the functions in MSCHAPv2 use the MD4 hash of the password anyway,
		// but given that MD4 is so vulnerable that breaking a hash is almost as
		// fast as computing it, it's just not worth it.
		password := []byte("password-from-database")

		if len(challenge) == 16 && len(response) == 50 {
			// See rfc2548 - 2.3.2. MS-CHAP2-Response
			ident := response[0]
			peerChallenge := response[2:18]
			peerResponse := response[26:50]
			ntResponse, err := rfc2759.GenerateNTResponse(challenge, peerChallenge, username, password)
			if err != nil {
				log.Printf("Cannot generate ntResponse for %s: %v", username, err)
				w.Write(r.Response(radius.CodeAccessReject))
				return
			}

			if bytes.Equal(ntResponse, peerResponse) {
				responsePacket := r.Response(radius.CodeAccessAccept)

				recvKey, err := rfc3079.MakeKey(ntResponse, password, false)
				if err != nil {
					log.Printf("Cannot make recvKey for %s: %v", username, err)
					w.Write(r.Response(radius.CodeAccessReject))
					return
				}

				sendKey, err := rfc3079.MakeKey(ntResponse, password, true)
				if err != nil {
					log.Printf("Cannot make sendKey for %s: %v", username, err)
					w.Write(r.Response(radius.CodeAccessReject))
					return
				}

				authenticatorResponse, err := rfc2759.GenerateAuthenticatorResponse(challenge, peerChallenge, ntResponse, username, password)
				if err != nil {
					log.Printf("Cannot generate authenticator response for %s: %v", username, err)
					w.Write(r.Response(radius.CodeAccessReject))
					return
				}

				success := make([]byte, 43)
				success[0] = ident
				copy(success[1:], authenticatorResponse)

				rfc2869.AcctInterimInterval_Add(responsePacket, rfc2869.AcctInterimInterval(3600))
				rfc2868.TunnelType_Add(responsePacket, 0, rfc2868.TunnelType_Value_L2TP)
				rfc2868.TunnelMediumType_Add(responsePacket, 0, rfc2868.TunnelMediumType_Value_IPv4)
				microsoft.MSCHAP2Success_Add(responsePacket, []byte(success))
				microsoft.MSMPPERecvKey_Add(responsePacket, recvKey)
				microsoft.MSMPPESendKey_Add(responsePacket, sendKey)
				microsoft.MSMPPEEncryptionPolicy_Add(responsePacket, microsoft.MSMPPEEncryptionPolicy_Value_EncryptionAllowed)
				microsoft.MSMPPEEncryptionTypes_Add(responsePacket, microsoft.MSMPPEEncryptionTypes_Value_RC440or128BitAllowed)

				log.Printf("Access granted to %s", username)
				w.Write(responsePacket)
				return
			}
		}

		log.Printf("Access denied for %s", username)
		w.Write(r.Response(radius.CodeAccessReject))
	}

	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(radiusSecret)),
	}

	log.Printf("Starting Radius server on :1812")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
