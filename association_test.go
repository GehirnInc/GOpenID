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
	assoc, err := CreateAssociation(rand.Reader, AssocHmacSha1, time.Unix(0, 0), false)
	if assert.Nil(t, err) {
		assert.Equal(t, assoc.GetAssocType(), AssocHmacSha1)

		handle, err := uuid.ParseHex(assoc.GetHandle())
		if assert.Nil(t, err) {
			assert.Equal(t, assoc.GetHandle(), handle.String())
		}

		assert.Equal(t, len(assoc.GetSecret()), AssocHmacSha1.GetSecretSize())

		expires := assoc.GetExpires()
		expected := issue.Add(AssociationLifetime)
		assert.True(t, expected.Equal(expires) || expected.After(expires))

		assert.False(t, assoc.IsStateless())
	}

	expires := time.Now().Add(time.Hour * 24 * 2)
	assoc, err = CreateAssociation(rand.Reader, AssocHmacSha256, expires, true)
	if assert.Nil(t, err) {
		assert.Equal(t, assoc.GetAssocType(), AssocHmacSha256)

		handle, err := uuid.ParseHex(assoc.GetHandle())
		if assert.Nil(t, err) {
			assert.Equal(t, assoc.GetHandle(), handle.String())
		}

		assert.Equal(t, len(assoc.GetSecret()), AssocHmacSha256.GetSecretSize())

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
					expected := EncodeBase64(mac.Sum(nil))
					if assert.Nil(t, err) {
						assert.Equal(t, sig.String(), string(expected))
					}
				}
			}
		}
	}
}
