package provider

import (
	"fmt"
	"github.com/GehirnInc/GOpenID"
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

type checkidRequestCase struct {
	request url.Values

	namespace gopenid.NamespaceURI
	mode      string
	stateless bool
	responses []interface{}
}

type checkidRequestAcceptedResponse struct {
	arg_identity  string
	arg_claimedId string

	identity  gopenid.MessageValue
	claimedId gopenid.MessageValue
	err       error
}

type checkidRequestRejectedResponse struct {
	mode gopenid.MessageValue

	setupUrl string
}

const (
	endpoint = "http://example.com/"
)

var (
	checkidRequestCases = []checkidRequestCase{
		checkidRequestCase{
			request: url.Values{
				"openid.ns":       []string{gopenid.NsOpenID20.String()},
				"openid.mode":     []string{"checkid_immediate"},
				"openid.realm":    []string{"http://example.com/"},
				"openid.returnTo": []string{"http://example.com/signin"},
			},
			namespace: gopenid.NsOpenID20,
			mode:      "checkid_immediate",
			stateless: true,
			responses: []interface{}{
				checkidRequestAcceptedResponse{
					arg_identity:  "",
					arg_claimedId: "",

					identity:  "",
					claimedId: "",
				},
				checkidRequestAcceptedResponse{
					arg_identity:  "testuser",
					arg_claimedId: "",

					err: ErrInvalidCheckIDRequest,
				},
				checkidRequestRejectedResponse{
					mode: "setup_needed",
					setupUrl: fmt.Sprintf("%s?%s", endpoint, url.Values{
						"openid.ns":       []string{gopenid.NsOpenID20.String()},
						"openid.mode":     []string{"checkid_setup"},
						"openid.realm":    []string{"http://example.com/"},
						"openid.returnTo": []string{"http://example.com/signin"},
					}.Encode()),
				},
			},
		},
		checkidRequestCase{
			request: url.Values{
				"openid.ns":       []string{gopenid.NsOpenID20.String()},
				"openid.mode":     []string{"checkid_setup"},
				"openid.realm":    []string{"http://example.com/"},
				"openid.returnTo": []string{"http://example.com/signin"},
			},
			namespace: gopenid.NsOpenID20,
			mode:      "checkid_setup",
			stateless: true,
			responses: []interface{}{
				checkidRequestRejectedResponse{
					mode: "cancel",
				},
			},
		},
		checkidRequestCase{
			request: url.Values{
				"openid.ns":         []string{gopenid.NsOpenID20.String()},
				"openid.identity":   []string{gopenid.NsIdentifierSelect.String()},
				"openid.claimed_id": []string{gopenid.NsIdentifierSelect.String()},
				"openid.mode":       []string{"checkid_immediate"},
				"openid.realm":      []string{"http://example.com/"},
				"openid.returnTo":   []string{"http://example.com/signin"},
			},
			namespace: gopenid.NsOpenID20,
			mode:      "checkid_immediate",
			stateless: true,
			responses: []interface{}{
				checkidRequestAcceptedResponse{
					arg_identity:  "",
					arg_claimedId: "",

					err: ErrInvalidCheckIDRequest,
				},
				checkidRequestAcceptedResponse{
					arg_identity:  "http://example.com/user",
					arg_claimedId: "",

					identity:  "http://example.com/user",
					claimedId: "http://example.com/user",
				},
				checkidRequestAcceptedResponse{
					arg_identity:  "http://example.com/user",
					arg_claimedId: "user",

					identity:  "http://example.com/user",
					claimedId: "user",
				},
			},
		},
		checkidRequestCase{
			request: url.Values{
				"openid.ns":         []string{gopenid.NsOpenID20.String()},
				"openid.identity":   []string{"http://example.com/user"},
				"openid.claimed_id": []string{"http://example.com/user"},
				"openid.mode":       []string{"checkid_immediate"},
				"openid.realm":      []string{"http://example.com/"},
				"openid.returnTo":   []string{"http://example.com/signin"},
			},
			namespace: gopenid.NsOpenID20,
			mode:      "checkid_immediate",
			stateless: true,
			responses: []interface{}{
				checkidRequestAcceptedResponse{
					arg_identity:  "",
					arg_claimedId: "",

					identity:  "http://example.com/user",
					claimedId: "http://example.com/user",
				},
				checkidRequestAcceptedResponse{
					arg_identity:  "http://user.example.com/",
					arg_claimedId: "",

					err: ErrInvalidCheckIDRequest,
				},
			},
		},
	}
)

func TestCheckIDRequest(t *testing.T) {
	for index, testCase := range checkidRequestCases {
		msg, err := gopenid.MessageFromQuery(testCase.request)
		if !assert.Nil(t, err) {
			t.Log("invalid request data in index %d", index)
		}

		req, err := checkIDRequestFromMessage("GET", msg)
		if !assert.Nil(t, err) {
			t.Logf("invalid request data in index %d, %v\n", index, err)
			continue
		}

		assert.Equal(t, req.GetNamespace(), testCase.namespace)
		assert.Equal(t, req.GetMode(), testCase.mode)

		for _, response_ := range testCase.responses {
			switch response_.(type) {
			case checkidRequestAcceptedResponse:
			case checkidRequestRejectedResponse:
			default:
				t.Fatal("invalid test case")
			}
		}
	}
}
