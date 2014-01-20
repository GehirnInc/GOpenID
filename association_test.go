package gopenid

import (
	"crypto/hmac"
	"crypto/rand"
	"github.com/nu7hatch/gouuid"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCreateAssociation(t *testing.T) {
	issue := time.Now()
	assoc, err := CreateAssociation(rand.Reader, ASSOC_HMAC_SHA1, 0, false)
	if assert.Nil(t, err) {
		assert.Equal(t, assoc.GetAssocType(), ASSOC_HMAC_SHA1)

		handle, err := uuid.ParseHex(assoc.GetHandle())
		if assert.Nil(t, err) {
			assert.Equal(t, assoc.GetHandle(), handle.String())
		}

		assert.Equal(t, len(assoc.GetSecret()), ASSOC_HMAC_SHA1.GetSecretSize())

		expires := time.Unix(assoc.GetExpires(), 0)
		expected := time.Unix(issue.Unix()+ASSOCIATION_LIFETIME, 0)
		assert.True(t, expected.Equal(expires) || expected.After(expires))

		assert.False(t, assoc.IsStateless())
	}

	expires := time.Unix(time.Now().Unix()+60*60*24*2, 0).Unix()
	assoc, err = CreateAssociation(rand.Reader, ASSOC_HMAC_SHA256, expires, true)
	if assert.Nil(t, err) {
		assert.Equal(t, assoc.GetAssocType(), ASSOC_HMAC_SHA256)

		handle, err := uuid.ParseHex(assoc.GetHandle())
		if assert.Nil(t, err) {
			assert.Equal(t, assoc.GetHandle(), handle.String())
		}

		assert.Equal(t, len(assoc.GetSecret()), ASSOC_HMAC_SHA256.GetSecretSize())

		assert.Equal(t, assoc.GetExpires(), expires)

		assert.True(t, assoc.IsStateless())
	}

	var (
		NsExt NamespaceURI = "http://example.com/"
	)

	msg := Message{
		namespace: NsOpenID20,
		nsuri2nsalias: map[NamespaceURI]string{
			"http://example.com/": "example",
		},
		nsalias2nsuri: map[string]NamespaceURI{
			"example": "http://example.com/",
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
			assert.Equal(t, signed, "mode,ns")

			sig, ok := msg.GetArg(NewMessageKey(NsOpenID20, "sig"))
			if assert.True(t, ok) {
				mac := hmac.New(assoc.assocType.hashFunc, assoc.GetSecret())
				kv, err := msg.ToKeyValue([]string{"openid.mode", "openid.ns"})
				if assert.Nil(t, err) {
					mac.Write(kv)
					expected, err := EncodeBase64(mac.Sum(nil))
					if assert.Nil(t, err) {
						assert.Equal(t, sig.String(), string(expected))
					}
				}
			}
		}
	}
}
