package provider

import (
	"github.com/GehirnInc/GOpenID"
	"time"
)

type Provider struct {
	store         gopenid.Store
	signer        *Signer
	endpoint      string
	assocLifetime int64
}

func NewProvider(endpoint string, store gopenid.Store, lifetime int64) *Provider {
	signer := NewSigner(store, lifetime)

	return &Provider{
		store:         store,
		signer:        signer,
		endpoint:      endpoint,
		assocLifetime: lifetime,
	}
}

func (p *Provider) EstablishSession(msg gopenid.Message) (Session, error) {
	return SessionFromMessage(p, msg)
}

func (p *Provider) getAssocExpires() int64 {
	return time.Now().Unix() + p.assocLifetime
}
