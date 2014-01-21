package provider

import (
	"crypto/rand"
	"errors"
	"github.com/GehirnInc/GOpenID"
	"strings"
	"time"
)

var (
	ErrAlreadySigned      = errors.New("response has been signed")
	ErrNotNeedsSigning    = errors.New("response does not need signing")
	ErrIdentityNotSet     = errors.New("identity not set")
	ErrIdentitySet        = errors.New("identity set")
	ErrIdentityNotMatched = errors.New("identity not matched")
	ErrMessageNotSigned   = errors.New("message is not signed")
)

type Signer struct {
	store    gopenid.AssociationStore
	lifetime int64
}

func NewSigner(store gopenid.AssociationStore, lifetime int64) *Signer {
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
	msg := req.GetMessage()
	verify := msg.Copy()

	assocHandle, ok := msg.GetArg(
		gopenid.NewMessageKey(msg.GetOpenIDNamespace(), "assoc_handle"),
	)
	if !ok {
		err = ErrMessageNotSigned
		return
	}

	_order, ok := msg.GetArg(
		gopenid.NewMessageKey(msg.GetOpenIDNamespace(), "signed"),
	)
	if !ok {
		err = ErrMessageNotSigned
		return
	}
	order := strings.Split(_order.String(), ",")

	sig, ok := msg.GetArg(
		gopenid.NewMessageKey(msg.GetOpenIDNamespace(), "sig"),
	)
	if !ok {
		err = ErrMessageNotSigned
		return
	}

	assoc, err := s.store.GetAssociation(assocHandle.String(), isStateless)
	if err != nil {
		return
	}

	err = assoc.Sign(verify, order)
	if err != nil {
		return
	}
	expected, _ := msg.GetArg(gopenid.NewMessageKey(verify.GetOpenIDNamespace(), "sig"))

	ok = sig == expected
	return
}

func (s *Signer) Sign(res *Response, assocHandle string) (err error) {
	assoc, err := s.getAssociation(assocHandle)
	if err != nil {
		return
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

func (s *Signer) getAssociation(assocHandle string) (assoc *gopenid.Association, err error) {
	var (
		DEFAULT_ASSOC_TYPE = gopenid.ASSOC_HMAC_SHA1
	)

	if assocHandle == "" {
		assoc, err = gopenid.CreateAssociation(
			rand.Reader,
			DEFAULT_ASSOC_TYPE,
			s.getExpires(),
			true,
		)
	} else {
		assoc, err = s.store.GetAssociation(assocHandle, false)
		if err == nil {
			if !assoc.IsValid() {
				assoc, err = gopenid.CreateAssociation(
					rand.Reader,
					assoc.GetAssocType(),
					s.getExpires(),
					true,
				)
			}
		} else if err == gopenid.ErrAssociationNotFound {
			assoc, err = gopenid.CreateAssociation(
				rand.Reader,
				DEFAULT_ASSOC_TYPE,
				s.getExpires(),
				true,
			)
		} else {
			return
		}
	}

	if err != nil {
		return
	}

	if assoc.IsStateless() {
		err = s.store.StoreAssociation(assoc)
		if err != nil {
			return
		}
	}

	return
}
