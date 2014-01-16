package gopenid

import (
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
}
