package provider

import (
	"errors"
	"github.com/GehirnInc/GOpenID"
	"github.com/GehirnInc/GOpenID/dh"
	"math/big"
)

var (
	ErrUnknownMode                       = errors.New("Unknown mode")
	ErrInvalidCheckIDRequest             = errors.New("invalid checkid_* request")
	ErrInvalidCheckAuthenticationRequest = errors.New("invalid checkid_authentication request")
	ErrInvalidAssociateRequest           = errors.New("invalid associate request")

	DefaultDhGen     = big.NewInt(2)
	DefaultDhModulus = new(big.Int).SetBytes([]byte{
		0xdc, 0xf9, 0x3a, 0x0b, 0x88, 0x39, 0x72, 0xec, 0x0e, 0x19,
		0x98, 0x9a, 0xc5, 0xa2, 0xce, 0x31, 0x0e, 0x1d, 0x37, 0x71,
		0x7e, 0x8d, 0x95, 0x71, 0xbb, 0x76, 0x23, 0x73, 0x18, 0x66,
		0xe6, 0x1e, 0xf7, 0x5a, 0x2e, 0x27, 0x89, 0x8b, 0x05, 0x7f,
		0x98, 0x91, 0xc2, 0xe2, 0x7a, 0x63, 0x9c, 0x3f, 0x29, 0xb6,
		0x08, 0x14, 0x58, 0x1c, 0xd3, 0xb2, 0xca, 0x39, 0x86, 0xd2,
		0x68, 0x37, 0x05, 0x57, 0x7d, 0x45, 0xc2, 0xe7, 0xe5, 0x2d,
		0xc8, 0x1c, 0x7a, 0x17, 0x18, 0x76, 0xe5, 0xce, 0xa7, 0x4b,
		0x14, 0x48, 0xbf, 0xdf, 0xaf, 0x18, 0x82, 0x8e, 0xfd, 0x25,
		0x19, 0xf1, 0x4e, 0x45, 0xe3, 0x82, 0x66, 0x34, 0xaf, 0x19,
		0x49, 0xe5, 0xb5, 0x35, 0xcc, 0x82, 0x9a, 0x48, 0x3b, 0x8a,
		0x76, 0x22, 0x3e, 0x5d, 0x49, 0x0a, 0x25, 0x7f, 0x05, 0xbd,
		0xff, 0x16, 0xf2, 0xfb, 0x22, 0xc5, 0x83, 0xab,
	})
)

type Request interface {
	GetMode() string
	GetNamespace() gopenid.NamespaceURI
	GetMessage() gopenid.Message
}

func RequestFromMessage(msg gopenid.Message) (Request, error) {
	mode, _ := msg.GetArg(gopenid.NewMessageKey(msg.GetOpenIDNamespace(), "mode"))
	switch mode {
	case "checkid_immediate":
		return checkIDRequestFromMessage(msg)
	case "checkid_setup":
		return checkIDRequestFromMessage(msg)
	case "associate":
		return associateRequestFromMessage(msg)
	case "check_authentication":
		return checkAuthenticationRequestFromMessage(msg)
	default:
		return nil, ErrUnknownMode
	}

}

type checkIDRequest struct {
	message gopenid.Message

	mode        gopenid.MessageValue
	claimedId   gopenid.MessageValue
	identity    gopenid.MessageValue
	assocHandle gopenid.MessageValue
	returnTo    gopenid.MessageValue
	realm       gopenid.MessageValue
}

func checkIDRequestFromMessage(msg gopenid.Message) (req *checkIDRequest, err error) {
	ns := msg.GetOpenIDNamespace()
	mode, _ := msg.GetArg(gopenid.NewMessageKey(ns, "mode"))

	claimedId, _ := msg.GetArg(gopenid.NewMessageKey(ns, "claimed_id"))
	identity, _ := msg.GetArg(gopenid.NewMessageKey(ns, "identity"))
	if (claimedId == "" && identity != "") || (claimedId != "" && identity == "") {
		// openid.claimed_id" and "openid.identity" SHALL be either both present or both absent
		err = ErrInvalidCheckIDRequest
		return
	}

	assocHandle, _ := msg.GetArg(gopenid.NewMessageKey(ns, "assoc_handle"))

	returnTo, _ := msg.GetArg(gopenid.NewMessageKey(ns, "return_to"))
	if returnTo != "" {
		_, err = ParseRealm(returnTo.String())
		if err != nil {
			return
		}
	}

	realm, _ := msg.GetArg(gopenid.NewMessageKey(ns, "realm"))
	if realm == "" && returnTo == "" {
		// openid.realm MUST be sent if openid.return_to is omitted
		err = ErrInvalidCheckIDRequest
		return
	} else if realm != "" {
		var parsed Realm
		parsed, err = ParseRealm(realm.String())
		if err != nil {
			return
		}

		if returnTo != "" && !parsed.Validate(returnTo.String()) {
			err = ErrInvalidCheckIDRequest
			return
		}
	} else {
		realm = returnTo
	}

	req = &checkIDRequest{
		message:     msg,
		mode:        mode,
		claimedId:   claimedId,
		identity:    identity,
		assocHandle: assocHandle,
		returnTo:    returnTo,
		realm:       realm,
	}
	return
}

func (req *checkIDRequest) GetNamespace() gopenid.NamespaceURI {
	return req.message.GetOpenIDNamespace()
}

func (req *checkIDRequest) GetMode() string {
	return req.mode.String()
}

func (req *checkIDRequest) GetMessage() gopenid.Message {
	return req.message
}

type checkAuthenticationRequest struct {
	message gopenid.Message

	mode          gopenid.MessageValue
	assocHandle   gopenid.MessageValue
	signed        gopenid.MessageValue
	sig           gopenid.MessageValue
	responseNonce gopenid.MessageValue
}

func checkAuthenticationRequestFromMessage(msg gopenid.Message) (req *checkAuthenticationRequest, err error) {
	ns := msg.GetOpenIDNamespace()

	if ns != gopenid.NsOpenID20 {
		err = ErrInvalidCheckAuthenticationRequest
		return
	}

	mode, _ := msg.GetArg(gopenid.NewMessageKey(ns, "mode"))

	assocHandle, ok := msg.GetArg(gopenid.NewMessageKey(ns, "assoc_handle"))
	if !ok {
		err = ErrInvalidCheckAuthenticationRequest
		return
	}

	signed, ok := msg.GetArg(gopenid.NewMessageKey(ns, "signed"))
	if !ok {
		err = ErrInvalidCheckAuthenticationRequest
		return
	}

	sig, ok := msg.GetArg(gopenid.NewMessageKey(ns, "sig"))
	if !ok {
		err = ErrInvalidCheckAuthenticationRequest
		return
	}

	responseNonce, ok := msg.GetArg(gopenid.NewMessageKey(ns, "response_nonce"))
	if !ok {
		err = ErrInvalidCheckAuthenticationRequest
		return
	}

	req = &checkAuthenticationRequest{
		message: msg,

		mode:          mode,
		assocHandle:   assocHandle,
		signed:        signed,
		sig:           sig,
		responseNonce: responseNonce,
	}
	return
}

func (req *checkAuthenticationRequest) GetMode() string {
	return req.mode.String()
}

func (req *checkAuthenticationRequest) GetNamespace() gopenid.NamespaceURI {
	return req.message.GetOpenIDNamespace()
}

func (req *checkAuthenticationRequest) GetMessage() gopenid.Message {
	return req.message
}

type associateRequest struct {
	message gopenid.Message
	err     error

	mode        gopenid.MessageValue
	assocType   gopenid.AssocType
	sessionType gopenid.SessionType

	dhParams         dh.Params
	dhConsumerPublic dh.PublicKey
}

func associateRequestFromMessage(msg gopenid.Message) (req *associateRequest, err error) {
	ns := msg.GetOpenIDNamespace()
	req = &associateRequest{
		message: msg,
	}

	req.mode, _ = msg.GetArg(gopenid.NewMessageKey(ns, "mode"))

	assocTypeName, _ := msg.GetArg(gopenid.NewMessageKey(ns, "assoc_type"))
	req.assocType, err = gopenid.GetAssocTypeByName(assocTypeName.String())
	if err != nil {
		req.err = err
	}

	sessionTypeName, _ := msg.GetArg(gopenid.NewMessageKey(ns, "session_type"))
	req.sessionType, err = gopenid.GetSessionTypeByName(sessionTypeName.String())
	if err != nil {
		req.err = err
	}

	if req.sessionType.Name() != gopenid.SessionNoEncryption.Name() {
		var (
			P *big.Int
			G *big.Int
		)
		PBase64, _ := msg.GetArg(gopenid.NewMessageKey(ns, "dh_modulus"))
		if PBase64 != "" {
			P, err = gopenid.Base64ToInt(PBase64.Bytes())
			if err != nil {
				err = ErrInvalidAssociateRequest
				return
			}
		} else {
			P = DefaultDhModulus
		}

		GBase64, _ := msg.GetArg(gopenid.NewMessageKey(ns, "dh_gen"))
		if GBase64 != "" {
			G, err = gopenid.Base64ToInt(GBase64.Bytes())
			if err != nil {
				err = ErrInvalidAssociateRequest
				return
			}
		} else {
			G = DefaultDhGen
		}
		req.dhParams = dh.Params{
			P: P,
			G: G,
		}

		var (
			Y *big.Int
		)
		YBase64, _ := msg.GetArg(gopenid.NewMessageKey(ns, "dh_consumer_public"))
		Y, err = gopenid.Base64ToInt(YBase64.Bytes())
		if err != nil {
			err = ErrInvalidAssociateRequest
			return
		}
		req.dhConsumerPublic = dh.PublicKey{
			Y: Y,
		}
	}

	return
}

func (req *associateRequest) GetMode() string {
	return req.mode.String()
}

func (req *associateRequest) GetNamespace() gopenid.NamespaceURI {
	return req.message.GetOpenIDNamespace()
}

func (req *associateRequest) GetMessage() gopenid.Message {
	return req.message
}
