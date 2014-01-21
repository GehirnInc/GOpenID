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
		return CheckIDRequestFromMessage(msg)
	case "checkid_setup":
		return CheckIDRequestFromMessage(msg)
	case "associate":
		return AssociateRequestFromMessage(msg)
	case "check_authentication":
		return CheckAuthenticationRequestFromMessage(msg)
	default:
		return nil, ErrUnknownMode
	}

}

type CheckIDRequest struct {
	message gopenid.Message

	mode        gopenid.MessageValue
	claimedId   gopenid.MessageValue
	identity    gopenid.MessageValue
	assocHandle gopenid.MessageValue
	returnTo    gopenid.MessageValue
	realm       gopenid.MessageValue
}

func CheckIDRequestFromMessage(msg gopenid.Message) (req *CheckIDRequest, err error) {
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
	}

	req = &CheckIDRequest{
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

func (req *CheckIDRequest) GetNamespace() gopenid.NamespaceURI {
	return req.message.GetOpenIDNamespace()
}

func (req *CheckIDRequest) GetMode() string {
	return req.mode.String()
}

func (req *CheckIDRequest) GetMessage() gopenid.Message {
	return req.message
}

type CheckAuthenticationRequest struct {
	message gopenid.Message

	mode          gopenid.MessageValue
	assocHandle   gopenid.MessageValue
	signed        gopenid.MessageValue
	sig           gopenid.MessageValue
	responseNonce gopenid.MessageValue
}

func CheckAuthenticationRequestFromMessage(msg gopenid.Message) (req *CheckAuthenticationRequest, err error) {
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

	req = &CheckAuthenticationRequest{
		message: msg,

		mode:          mode,
		assocHandle:   assocHandle,
		signed:        signed,
		sig:           sig,
		responseNonce: responseNonce,
	}
	return
}

func (req *CheckAuthenticationRequest) GetMode() string {
	return req.mode.String()
}

func (req *CheckAuthenticationRequest) GetNamespace() gopenid.NamespaceURI {
	return req.message.GetOpenIDNamespace()
}

func (req *CheckAuthenticationRequest) GetMessage() gopenid.Message {
	return req.message
}

type AssociateRequest struct {
	message gopenid.Message

	mode        gopenid.MessageValue
	assocType   gopenid.AssocType
	sessionType gopenid.SessionType

	dhParams         dh.Params
	dhConsumerPublic dh.PublicKey
}

func AssociateRequestFromMessage(msg gopenid.Message) (req *AssociateRequest, err error) {
	ns := msg.GetOpenIDNamespace()
	req = &AssociateRequest{
		message: msg,
	}

	req.mode, _ = msg.GetArg(gopenid.NewMessageKey(ns, "mode"))

	assocTypeName, _ := msg.GetArg(gopenid.NewMessageKey(ns, "assoc_type"))
	req.assocType, err = gopenid.GetAssocTypeByName(assocTypeName.String())
	if err != nil {
		err = ErrInvalidAssociateRequest
		return
	}

	sessionTypeName, _ := msg.GetArg(gopenid.NewMessageKey(ns, "session_type"))
	req.sessionType, err = gopenid.GetSessionTypeByName(sessionTypeName.String())
	if err != nil {
		err = ErrInvalidAssociateRequest
		return
	}

	if req.sessionType.Name() != gopenid.SESSION_NO_ENCRYPTION.Name() {
		var (
			P *big.Int
			G *big.Int
		)
		PBase64, ok := msg.GetArg(gopenid.NewMessageKey(ns, "dh_modulus"))
		if !ok {
			err = ErrInvalidAssociateRequest
			return
		}
		P, err = gopenid.Base64ToInt(PBase64.Bytes())
		if err != nil {
			err = ErrInvalidAssociateRequest
			return
		}

		GBase64, _ := msg.GetArg(gopenid.NewMessageKey(ns, "dh_gen"))
		G, err = gopenid.Base64ToInt(GBase64.Bytes())
		if err != nil {
			err = ErrInvalidAssociateRequest
			return
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

func (req *AssociateRequest) GetMode() string {
	return req.mode.String()
}

func (req *AssociateRequest) GetNamespace() gopenid.NamespaceURI {
	return req.message.GetOpenIDNamespace()
}

func (req *AssociateRequest) GetMessage() gopenid.Message {
	return req.message
}
