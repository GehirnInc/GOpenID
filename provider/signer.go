package provider

import (
	"crypto/rand"
	"errors"
	"github.com/GehirnInc/GOpenID"
	"time"
)

var (
	ErrAlreadySigned      = errors.New("response has been signed")
	ErrNotNeedsSigning    = errors.New("response does not need signing")
	ErrIdentityNotSet     = errors.New("identity not set")
	ErrIdentitySet        = errors.New("identity set")
	ErrIdentityNotMatched = errors.New("identity not matched")
)

type Signer struct {
	store    gopenid.AssociationStore
	lifetime int64
}

func (s *Signer) Invalidate(handle string, isStateless bool) (err error) {
	assoc, err := s.store.GetAssociation(handle, isStateless)
	if err != nil {
		return
	}

	err = s.store.DeleteAssociation(assoc)
	return
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
