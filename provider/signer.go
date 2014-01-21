package provider

import (
	"crypto/rand"
	"errors"
	"github.com/GehirnInc/GOpenID"
	"strings"
	"time"
)

var (
	ErrAlreadySigned         = errors.New("response has been signed")
	ErrNotNeedsSigning       = errors.New("response does not need signing")
	ErrIdentityNotSet        = errors.New("identity not set")
	ErrIdentitySet           = errors.New("identity set")
	ErrIdentityNotMatched    = errors.New("identity not matched")
	ErrMessageNotSigned      = errors.New("message is not signed")
	ErrVerifyingNotSupported = errors.New("verifying not supported")
)

type Signer struct {
	store    gopenid.Store
	lifetime int64
}

func NewSigner(store gopenid.Store, lifetime int64) *Signer {
	return &Signer{
		store:    store,
		lifetime: lifetime,
	}
}

func (s *Signer) Invalidate(handle string, isStateless bool) (err error) {
	assoc, err := s.store.GetAssociation(handle, isStateless)
	if err != nil {
		return
	}

	err = s.store.DeleteAssociation(assoc)
	return
}

func (s *Signer) Verify(req Request, isStateless bool) (ok bool, err error) {
	var (
		assocHandle gopenid.MessageValue
		signed      gopenid.MessageValue
		sig         gopenid.MessageValue
	)

	switch ret := req.(type) {
	case *CheckAuthenticationRequest:
		assocHandle = ret.assocHandle
		signed = ret.signed
		sig = ret.sig
	default:
		err = ErrVerifyingNotSupported
		return
	}

	assoc, err := s.store.GetAssociation(assocHandle.String(), isStateless)
	if err != nil {
		return
	}

	// signing
	msg := req.GetMessage()
	verify := msg.Copy()
	if err = assoc.Sign(verify, strings.Split(signed.String(), ",")); err != nil {
		return
	}

	expected, _ := verify.GetArg(
		gopenid.NewMessageKey(verify.GetOpenIDNamespace(), "sig"),
	)
	ok = sig == expected

	return
}

func (s *Signer) Sign(res *Response, assocHandle string) (err error) {
	var assoc *gopenid.Association

	if assocHandle == "" {
		assoc, err = gopenid.CreateAssociation(
			rand.Reader,
			gopenid.ASSOC_HMAC_SHA256,
			s.getExpires(),
			true,
		)
	} else {
		assoc, err = s.store.GetAssociation(assocHandle, false)
		if err == nil {
			if !assoc.IsValid() {
				res.AddArg(
					gopenid.NewMessageKey(res.GetNamespace(), "invalidate_handle"),
					gopenid.MessageValue(assocHandle),
				)

				assoc, err = gopenid.CreateAssociation(
					rand.Reader,
					assoc.GetAssocType(),
					s.getExpires(),
					true,
				)
			}
		} else if err == gopenid.ErrAssociationNotFound {
			res.AddArg(
				gopenid.NewMessageKey(res.GetNamespace(), "invalidate_handle"),
				gopenid.MessageValue(assocHandle),
			)

			assoc, err = gopenid.CreateAssociation(
				rand.Reader,
				gopenid.ASSOC_HMAC_SHA256,
				s.getExpires(),
				true,
			)
		} else {
			return
		}
	}

	order := []string{
		"op_endpoint",
		"return_to",
		"response_nonce",
		"assoc_handle",
		"claimed_id",
		"identity",
	}

	if _, ok := res.message.GetArg(gopenid.NewMessageKey(res.message.GetOpenIDNamespace(), "identity")); !ok {
		order = order[:5]
	}

	if _, ok := res.message.GetArg(gopenid.NewMessageKey(res.message.GetOpenIDNamespace(), "claimed_id")); !ok {
		copy(order[4:], order[len(order)-1:])
		order = order[:len(order)-1]
	}

	return assoc.Sign(res.message, order)
}

func (s *Signer) getExpires() int64 {
	return time.Now().Unix() + s.lifetime
}
