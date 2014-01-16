package gopenid

import (
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"github.com/nu7hatch/gouuid"
	"hash"
	"io"
	"time"
)

const (
	ASSOCIATION_LIFETIME = 60 * 60 * 24 * 1
)

var (
	ErrGeneratingAssociationFailed = errors.New("generating association failed")

	ASSOC_HMAC_SHA1 = AssocType{
		name:       "HMAC-SHA1",
		hashFunc:   sha1.New,
		secretSize: sha1.Size,
	}
	ASSOC_HMAC_SHA256 = AssocType{
		name:       "HMAC-SHA256",
		hashFunc:   sha256.New,
		secretSize: sha256.Size,
	}
)

type AssocType struct {
	name       string
	hashFunc   func() hash.Hash
	secretSize int
}

func (t *AssocType) Name() string {
	return t.name
}

func (t *AssocType) GetSecretSize() int {
	return t.secretSize
}

type Association struct {
	assocType   AssocType
	handle      string
	secret      []byte
	expires     int64
	isStateless bool
}

func NewAssociation(assocType AssocType, handle string, secret []byte, expires int64, isStateless bool) *Association {
	if expires < 1 {
		expires = time.Now().Unix() + ASSOCIATION_LIFETIME
	}

	return &Association{
		assocType:   assocType,
		handle:      handle,
		secret:      secret,
		expires:     expires,
		isStateless: isStateless,
	}
}

func CreateAssociation(random io.Reader, assocType AssocType, expires int64, isStateless bool) (assoc *Association, err error) {
	handle, err := uuid.NewV4()
	if err != nil {
		err = ErrGeneratingAssociationFailed
		return
	}

	secret := make([]byte, assocType.GetSecretSize())
	_, err = io.ReadFull(random, secret)
	if err != nil {
		err = ErrGeneratingAssociationFailed
		return
	}

	assoc = NewAssociation(assocType, handle.String(), secret, expires, isStateless)
	return
}

func (assoc *Association) GetAssocType() AssocType {
	return assoc.assocType
}

func (assoc *Association) GetHandle() string {
	return assoc.handle
}

func (assoc *Association) GetSecret() []byte {
	return assoc.secret
}

func (assoc *Association) GetExpires() int64 {
	return assoc.expires
}

func (assoc *Association) IsStateless() bool {
	return assoc.isStateless
}
