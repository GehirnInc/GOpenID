package provider

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type RealmTestCase struct {
	RawURL   string
	expected Realm
	err      error
}

var (
	RealmTestCases = []RealmTestCase{
		RealmTestCase{
			RawURL: "http://example.com/",
			expected: Realm{
				Scheme:   "http",
				Host:     "example.com",
				Port:     "",
				Path:     "/",
				RawQuery: "",
				Wildcard: false,
			},
		},
		RealmTestCase{
			RawURL: "http://example.com:80/",
			expected: Realm{
				Scheme:   "http",
				Host:     "example.com",
				Port:     "",
				Path:     "/",
				RawQuery: "",
				Wildcard: false,
			},
		},
		RealmTestCase{
			RawURL: "http://example.com:8080/",
			expected: Realm{
				Scheme:   "http",
				Host:     "example.com",
				Port:     "8080",
				Path:     "/",
				RawQuery: "",
				Wildcard: false,
			},
		},
		RealmTestCase{
			RawURL: "http://example.com/dir/",
			expected: Realm{
				Scheme:   "http",
				Host:     "example.com",
				Port:     "",
				Path:     "/dir/",
				RawQuery: "",
				Wildcard: false,
			},
		},
		RealmTestCase{
			RawURL: "http://example.com/?foo=bar",
			expected: Realm{
				Scheme:   "http",
				Host:     "example.com",
				Port:     "",
				Path:     "/",
				RawQuery: "foo=bar",
				Wildcard: false,
			},
		},
		RealmTestCase{
			RawURL: "http://*.example.com/",
			expected: Realm{
				Scheme:   "http",
				Host:     ".example.com",
				Port:     "",
				Path:     "/",
				RawQuery: "",
				Wildcard: true,
			},
		},
		RealmTestCase{
			RawURL: "ftp://example.com/",
			err:    ErrMalformedRealm,
		},
		RealmTestCase{
			RawURL: "http://www.*.example.com/",
			err:    ErrMalformedRealm,
		},
		RealmTestCase{
			RawURL: "http://*.example.*/",
			err:    ErrMalformedRealm,
		},
		RealmTestCase{
			RawURL: "http://example.com/#fragment",
			err:    ErrMalformedRealm,
		},
	}
)

func TestParseRealm(t *testing.T) {
	for _, testCase := range RealmTestCases {
		parsed, err := ParseRealm(testCase.RawURL)
		if testCase.err == nil {
			if assert.Nil(t, err) {
				assert.Equal(t, parsed, testCase.expected)
			}
		} else {
			if !assert.Equal(t, err, testCase.err) {
			}
		}
	}
}

func TestRealm(t *testing.T) {
	// scheme, hostname, port
	realm, _ := ParseRealm("http://example.com/")
	assert.True(t, realm.Validate("http://example.com/"))
	assert.False(t, realm.Validate("https://example.com/"))
	assert.False(t, realm.Validate("http://example.com:8080/"))
	assert.False(t, realm.Validate("http://www.example.com/"))
	assert.False(t, realm.Validate("http://example.com.net/"))

	realm, _ = ParseRealm("http://example.com:8080/")
	assert.False(t, realm.Validate("http://example.com/"))
	assert.True(t, realm.Validate("http://example.com:8080/"))

	// path
	realm, _ = ParseRealm("http://example.com/abc/")
	assert.False(t, realm.Validate("http://example.com/"))
	assert.True(t, realm.Validate("http://example.com/abc/"))
	assert.True(t, realm.Validate("http://example.com/abc/?foo=bar"))
	assert.True(t, realm.Validate("http://example.com/abc/#baz"))
	assert.True(t, realm.Validate("http://example.com/abc/def/"))
	assert.True(t, realm.Validate("http://example.com/abc/def/?foo=bar"))

	realm, _ = ParseRealm("http://example.com/abc")
	assert.True(t, realm.Validate("http://example.com/abc"))
	assert.True(t, realm.Validate("http://example.com/abc/def"))
	assert.False(t, realm.Validate("http://example.com/abcdef"))

	// query
	realm, _ = ParseRealm("http://example.com/?foo=bar")
	assert.False(t, realm.Validate("http://example.com/"))
	assert.True(t, realm.Validate("http://example.com/?foo=bar"))
	assert.True(t, realm.Validate("http://example.com/?foo=bar#baz"))
	assert.True(t, realm.Validate("http://example.com/?foo=bar&hoge=fuga"))
	assert.False(t, realm.Validate("http://example.com/?hoge=fuga&foo=bar"))
}
