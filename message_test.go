package gopenid

import (
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
				namespace: NsOpenID20,
				args: map[MessageKey]MessageValue{
					NewMessageKey(NsOpenID20, "mode"): "checkid_immediate",
				},
			},
			err: nil,
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
				args: map[MessageKey]MessageValue{
					NewMessageKey("http://example.com/", "key"): "value",
				},
			},
			err: nil,
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
	}
)

func TestMessageFromQuery(t *testing.T) {
	assert.True(t, sort.StringsAreSorted(ProtocolFields))

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
