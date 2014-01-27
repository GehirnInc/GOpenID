package gopenid

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/nu7hatch/gouuid"
	"hash"
	"io"
	"strings"
	"time"
)

const (
	AssociationLifetime = 60 * 60 * 24 * 1
)

var (
	ErrGeneratingAssociationFailed = errors.New("generating association failed")
	ErrAssociationNotFound         = errors.New("association not found")
	ErrUnknownSessionType          = errors.New("unknown session type")
	ErrUnknownAssocType            = errors.New("unknown association type")

	AssocHmacSha1 = AssocType{
		name:       "HMAC-SHA1",
		hashFunc:   sha1.New,
		secretSize: sha1.Size,
	}
	AssocHmacSha256 = AssocType{
		name:       "HMAC-SHA256",
		hashFunc:   sha256.New,
		secretSize: sha256.Size,
	}

	SessionDhSha1 = SessionType{
		name: "DH-SHA1",
		assocTypes: []AssocType{
			AssocHmacSha1,
		},
	}
	SessionDhSha256 = SessionType{
		name: "DH-SHA256",
		assocTypes: []AssocType{
			AssocHmacSha256,
		},
	}
	SessionNoEncryption = SessionType{
		name: "no-encryption",
		assocTypes: []AssocType{
			AssocHmacSha1,
			AssocHmacSha256,
		},
	}

	DefaultAssoc   = AssocHmacSha256
	DefaultSession = SessionDhSha256
)

type AssocType struct {
	name       string
	hashFunc   func() hash.Hash
	secretSize int
}

func (t *AssocType) Name() string {
	return t.name
}

func (t *AssocType) Hash() hash.Hash {
	return t.hashFunc()
}

func (t *AssocType) GetSecretSize() int {
	return t.secretSize
}

func GetAssocTypeByName(name string) (assocType AssocType, err error) {
	switch name {
	case "HMAC-SHA1":
		assocType = AssocHmacSha1
	case "HMAC-SHA256":
		assocType = AssocHmacSha256
	default:
		err = ErrUnknownAssocType
	}

	return
}

type SessionType struct {
	name       string
	assocTypes []AssocType
}

func (t *SessionType) Name() string {
	return t.name
}

func GetSessionTypeByName(name string) (sessionType SessionType, err error) {
	switch name {
	case "no-encryption":
		sessionType = SessionNoEncryption
	case "DH-SHA1":
		sessionType = SessionDhSha1
	case "DH-SHA256":
		sessionType = SessionDhSha256
	default:
		err = ErrUnknownSessionType
	}

	return
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
		expires = time.Now().Unix() + AssociationLifetime
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

func (assoc *Association) IsValid() bool {
	return time.Now().Before(time.Unix(assoc.GetExpires(), 0))
}

func (assoc *Association) IsStateless() bool {
	return assoc.isStateless
}

func (assoc *Association) Sign(msg Message, signed []string) (err error) {
	order := make([]string, len(signed))
	for i, key := range signed {
		order[i] = fmt.Sprintf("openid.%s", key)
	}

	msg.AddArg(
		NewMessageKey(msg.GetOpenIDNamespace(), "assoc_handle"),
		MessageValue(assoc.GetHandle()),
	)

	kv, err := msg.ToKeyValue(order)
	if err != nil {
		return
	}

	mac := hmac.New(assoc.assocType.hashFunc, assoc.secret)
	mac.Write(kv)
	sig := EncodeBase64(mac.Sum(nil))

	msg.AddArg(
		NewMessageKey(msg.GetOpenIDNamespace(), "signed"),
		MessageValue(strings.Join(signed, ",")),
	)
	msg.AddArg(
		NewMessageKey(msg.GetOpenIDNamespace(), "sig"),
		MessageValue(sig),
	)

	return
}
