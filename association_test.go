package gopenid

import (
	"crypto/hmac"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAssociation(t *testing.T) {
	handle := uuid.New().String()
	secret := make([]byte, DefaultAssoc.GetSecretSize())
	_, err := io.ReadFull(rand.Reader, secret)
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	expires := time.Now().Add(time.Hour * 24 * 2)

	assoc := NewAssociation(DefaultAssoc, handle, secret, expires, true)

	var NsExt NamespaceURI = "http://example.com/"

	msg := Message{
		namespace: NsOpenID20,
		nsuri2nsalias: map[NamespaceURI]string{
			NsExt: "example",
		},
		nsalias2nsuri: map[string]NamespaceURI{
			"example": NsExt,
		},
		args: map[MessageKey]MessageValue{
			NewMessageKey(NsExt, "foo"):            "bar",
			NewMessageKey(NsExt, "hoge"):           "fuga",
			NewMessageKey(NsOpenID20, "mode"):      "checkid_immediate",
			NewMessageKey(NsOpenID20, "return_to"): "http://www.example.com/",
		},
	}

	err = assoc.Sign(msg, []string{"mode", "ns"})
	if assert.Nil(t, err) {
		signed, ok := msg.GetArg(NewMessageKey(NsOpenID20, "signed"))
		if assert.True(t, ok) {
			assert.Equal(t, signed.String(), "mode,ns")

			sig, ok := msg.GetArg(NewMessageKey(NsOpenID20, "sig"))
			if assert.True(t, ok) {
				mac := hmac.New(assoc.assocType.hashFunc, assoc.GetSecret())
				kv, err := msg.ToKeyValue([]string{"openid.mode", "openid.ns"})
				if assert.Nil(t, err) {
					mac.Write(kv)
					expected := EncodeBase64(mac.Sum(nil))
					if assert.Nil(t, err) {
						assert.Equal(t, sig.String(), string(expected))
					}
				}
			}
		}
	}
}
