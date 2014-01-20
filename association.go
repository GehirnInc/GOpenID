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
	ASSOCIATION_LIFETIME = 60 * 60 * 24 * 1
)

var (
	ErrGeneratingAssociationFailed = errors.New("generating association failed")
	ErrAssociationNotFound         = errors.New("association not found")
	ErrUnknownSessionType          = errors.New("unknown session type")
	ErrUnknownAssocType            = errors.New("unknown association type")

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

	SESSION_DH_SHA1 = SessionType{
		name: "DH-SHA1",
		assocTypes: []AssocType{
			ASSOC_HMAC_SHA1,
		},
	}
	SESSION_DH_SHA256 = SessionType{
		name: "DH-SHA256",
		assocTypes: []AssocType{
			ASSOC_HMAC_SHA256,
		},
	}
	SESSION_NO_ENCRYPTION = SessionType{
		name: "no-encryption",
		assocTypes: []AssocType{
			ASSOC_HMAC_SHA1,
			ASSOC_HMAC_SHA256,
		},
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

func GetAssocTypeByName(name string) (assocType AssocType, err error) {
	switch name {
	case "HMAC-SHA1":
		assocType = ASSOC_HMAC_SHA1
	case "HMAC-SHA256":
		assocType = ASSOC_HMAC_SHA256
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
		sessionType = SESSION_NO_ENCRYPTION
	case "DH-SHA1":
		sessionType = SESSION_DH_SHA1
	case "DH-SHA256":
		sessionType = SESSION_DH_SHA256
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

	mac := hmac.New(assoc.assocType.hashFunc, assoc.secret)
	kv, err := msg.ToKeyValue(order)
	if err != nil {
		return
	}
	mac.Write(kv)
	sig, err := EncodeBase64(mac.Sum(nil))
	if err != nil {
		return
	}

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
