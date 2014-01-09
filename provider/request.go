package provider

import (
	"errors"
	"github.com/GehirnInc/GOpenID"
	"net/url"
	"time"
)

var (
	ErrUnknownMode           = errors.New("Unknown mode")
	ErrInvalidCheckIDRequest = errors.New("invalid checkid_* request")
)

type Request interface {
	GetMode() string
	GetNamespace() gopenid.NamespaceURI
}

func RequestFromMessage(msg gopenid.Message, endpoint string) (Request, error) {
	mode, _ := msg.GetArg(gopenid.NewMessageKey(msg.GetOpenIDNamespace(), "mode"))
	switch mode {
	case "checkid_immediate":
		return CheckIDRequestFromMessage(msg, endpoint)
	case "checkid_setup":
		return CheckIDRequestFromMessage(msg, endpoint)
	default:
		return nil, ErrUnknownMode
	}

}

type CheckIDRequest struct {
	message  gopenid.Message
	endpoint string

	mode        gopenid.MessageValue
	claimedId   gopenid.MessageValue
	identity    gopenid.MessageValue
	assocHandle gopenid.MessageValue
	returnTo    gopenid.MessageValue
	realm       gopenid.MessageValue
}

func CheckIDRequestFromMessage(msg gopenid.Message, endpoint string) (req *CheckIDRequest, err error) {
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
		endpoint:    endpoint,
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

func (req *CheckIDRequest) IsStateless() bool {
	return req.assocHandle == ""
}

func (req *CheckIDRequest) Accept(identity, claimedId string) (res *Response, err error) {
	var (
		msgIdentity  gopenid.MessageValue
		msgClaimedId gopenid.MessageValue
	)

	if req.identity.String() == gopenid.NsIdentifierSelect.String() {
		if identity == "" {
			err = ErrInvalidCheckIDRequest
			return
		}

		msgIdentity = gopenid.MessageValue(identity)
		msgClaimedId = gopenid.MessageValue(claimedId)
		if msgClaimedId == "" {
			msgClaimedId = msgIdentity
		}
	} else if req.identity != "" {
		if identity != "" && req.identity.String() != identity {
			err = ErrInvalidCheckIDRequest
			return
		}
		msgIdentity = gopenid.MessageValue(req.identity)
		msgClaimedId = gopenid.MessageValue(req.claimedId)
	} else if identity != "" {
		err = ErrInvalidCheckIDRequest
		return
	}

	nonce := gopenid.GenerateNonce(time.Now().UTC())

	res = NewResponse(req)
	res.AddArg(gopenid.NewMessageKey(req.GetNamespace(), "mode"), "id_res")
	res.AddArg(gopenid.NewMessageKey(req.GetNamespace(), "op_endpoint"), gopenid.MessageValue(req.endpoint))
	res.AddArg(gopenid.NewMessageKey(req.GetNamespace(), "identity"), msgIdentity)
	res.AddArg(gopenid.NewMessageKey(req.GetNamespace(), "claimed_id"), msgClaimedId)
	res.AddArg(gopenid.NewMessageKey(req.GetNamespace(), "return_to"), req.returnTo)
	res.AddArg(gopenid.NewMessageKey(req.GetNamespace(), "response_nonce"), nonce)

	return
}

func (req *CheckIDRequest) Reject() *Response {
	res := NewResponse(req)

	var mode gopenid.MessageValue
	if req.mode == "checkid_immediate" {
		setupmsg := req.message
		setupmsg.AddArg(gopenid.NewMessageKey(req.GetNamespace(), "mode"), "checkid_setup")
		setupUrl, _ := url.Parse(req.endpoint)
		setupUrl.RawQuery = setupmsg.ToQuery().Encode()

		mode = "setup_needed"
		res.AddArg(
			gopenid.NewMessageKey(req.GetNamespace(), "user_setup_url"),
			gopenid.MessageValue(setupUrl.String()),
		)
	} else {
		mode = "cancel"
	}
	res.AddArg(gopenid.NewMessageKey(req.GetNamespace(), "mode"), mode)

	return res
}
