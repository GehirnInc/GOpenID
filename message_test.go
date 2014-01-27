package gopenid

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/url"
	"sort"
	"testing"
)

type messageFromQueryCase struct {
	query    url.Values
	expected Message
	err      error
}

var (
	messageFromQueryCases = []messageFromQueryCase{
		messageFromQueryCase{
			query: url.Values{
				"openid.ns": []string{
					NsOpenID20.String(),
				},
				"openid.mode": []string{
					"checkid_immediate",
				},
			},
			expected: Message{
				namespace:     NsOpenID20,
				nsuri2nsalias: make(map[NamespaceURI]string),
				nsalias2nsuri: make(map[string]NamespaceURI),
				args: map[MessageKey]MessageValue{
					NewMessageKey(NsOpenID20, "mode"): "checkid_immediate",
				},
			},
		},
		messageFromQueryCase{
			query: url.Values{
				"openid.ns": []string{
					NsOpenID20.String(),
				},
				"openid.ns.example": []string{
					"http://example.com/",
				},
				"openid.example.key": []string{
					"value",
				},
			},
			expected: Message{
				namespace: NsOpenID20,
				nsuri2nsalias: map[NamespaceURI]string{
					"http://example.com/": "example",
				},
				nsalias2nsuri: map[string]NamespaceURI{
					"example": "http://example.com/",
				},
				args: map[MessageKey]MessageValue{
					NewMessageKey("http://example.com/", "key"): "value",
				},
			},
		},
		messageFromQueryCase{
			query: url.Values{
				"openid.ns": []string{
					NsOpenID20.String(),
				},
				"openid.mode": []string{
					"checkid_immediate",
					"checkid_setup",
				},
			},
			err: ErrMalformedMessage,
		},
		messageFromQueryCase{
			query: url.Values{
				"openid.ns": []string{
					NsOpenID20.String(),
				},
				"openid.ns.mode.ext": []string{
					"http://example.com/",
				},
			},
			err: ErrMalformedMessage,
		},
		messageFromQueryCase{
			query: url.Values{
				"openid.ns": []string{
					NsOpenID20.String(),
				},
				"openid.ns.mode": []string{
					"http://example.com/",
				},
			},
			err: ErrMalformedMessage,
		},
		messageFromQueryCase{
			query: url.Values{
				"openid.mode": []string{
					"checkid_immediate",
				},
			},
			expected: Message{
				namespace:     NsOpenID11,
				nsuri2nsalias: make(map[NamespaceURI]string),
				nsalias2nsuri: make(map[string]NamespaceURI),
				args: map[MessageKey]MessageValue{
					NewMessageKey(NsOpenID11, "mode"): "checkid_immediate",
				},
			},
		},
		messageFromQueryCase{
			query: url.Values{
				"openid.ns": []string{
					"http://example.com/",
				},
			},
			err: ErrUnsupportedVersion,
		},
	}
)

func TestMessageFromQuery(t *testing.T) {
	assert.True(t, sort.StringsAreSorted(protocolFields))

	for _, testCase := range messageFromQueryCases {
		message, err := MessageFromQuery(testCase.query)
		if err == nil {
			assert.Equal(t, message, testCase.expected)
		} else {
			if !assert.Equal(t, err, testCase.err) {
				fmt.Println(testCase.query)
			}
		}
	}
}

func TestMessage(t *testing.T) {
	var (
		NsExt   NamespaceURI = "http://example.com/"
		NsDummy NamespaceURI = "http://dummy.example.com/"
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

	assert.Equal(t, msg.GetOpenIDNamespace(), NsOpenID20)

	if nsuri, ok := msg.GetNamespaceURI("example"); assert.True(t, ok) {
		assert.Equal(t, nsuri, "http://example.com/")
	}

	if nsalias, ok := msg.GetNamespaceAlias("http://example.com/"); assert.True(t, ok) {
		assert.Equal(t, nsalias, "example")
	}

	if arg, ok := msg.GetArg(NewMessageKey(NsExt, "foo")); assert.True(t, ok) {
		assert.Equal(t, arg, "bar")
	}
	if arg, ok := msg.GetArg(NewMessageKey(NsExt, "hoge")); assert.True(t, ok) {
		assert.Equal(t, arg, "fuga")
	}
	if arg, ok := msg.GetArg(NewMessageKey(NsOpenID20, "mode")); assert.True(t, ok) {
		assert.Equal(t, arg, "checkid_immediate")
	}
	if arg, ok := msg.GetArg(NewMessageKey(NsOpenID20, "return_to")); assert.True(t, ok) {
		assert.Equal(t, arg, "http://www.example.com/")
	}
	_, ok := msg.GetArg(NewMessageKey(NsOpenID20, "notgiven"))
	assert.False(t, ok)

	assert.Equal(t,
		msg.GetArgs(NsOpenID20),
		map[MessageKey]MessageValue{
			NewMessageKey(NsOpenID20, "mode"):      "checkid_immediate",
			NewMessageKey(NsOpenID20, "return_to"): "http://www.example.com/",
		},
	)
	assert.Equal(t,
		msg.GetArgs(NsExt),
		map[MessageKey]MessageValue{
			NewMessageKey(NsExt, "foo"):  "bar",
			NewMessageKey(NsExt, "hoge"): "fuga",
		},
	)
	assert.Equal(t, msg.GetArgs(NsDummy), map[MessageKey]MessageValue{})

	assert.Equal(t,
		msg.ToQuery(),
		url.Values{
			"openid.ns":           []string{NsOpenID20.String()},
			"openid.ns.example":   []string{"http://example.com/"},
			"openid.example.foo":  []string{"bar"},
			"openid.example.hoge": []string{"fuga"},
			"openid.mode":         []string{"checkid_immediate"},
			"openid.return_to":    []string{"http://www.example.com/"},
		},
	)

	if kv, err := msg.ToKeyValue([]string{"openid.ns", "openid.return_to"}); assert.Nil(t, err) {
		expected := bytes.Join([][]byte{
			[]byte(fmt.Sprintf("ns:%s", NsOpenID20.String())),
			[]byte("return_to:http://www.example.com/"),
			nil,
		}, []byte{'\n'})
		assert.Equal(t, kv, expected)
	}

	assert.Equal(t,
		msg,
		msg.Copy(),
	)
}
