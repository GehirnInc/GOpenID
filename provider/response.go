package provider

import (
	"github.com/GehirnInc/GOpenID"
	"net/url"
)

type Response interface {
	NeedsRedirect() bool
	IsPermanently() bool
	GetRedirectTo() string
	GetBody() []byte
	GetContentType() string
}

type openIDResponse struct {
	request       Request
	message       gopenid.Message
	needsRedirect bool
	isPermanently bool
	contentType   string
	returnTo      string
}

func newOpenIDResponse(req Request) *openIDResponse {
	res := &openIDResponse{
		request: req,
		message: gopenid.NewMessage(req.GetNamespace()),
	}

	switch ret := req.(type) {
	case *checkIDRequest:
		res.needsRedirect = true
		res.isPermanently = false

		returnTo, _ := ret.message.GetArg(gopenid.NewMessageKey(ret.GetNamespace(), "return_to"))
		res.returnTo = returnTo.String()
	case *associateRequest:
		res.needsRedirect = false
		res.contentType = "text/plain;charset=utf8"
	case *checkAuthenticationRequest:
		res.needsRedirect = false
		res.contentType = "text/plain;charset=utf8"
	}

	return res
}

func (res *openIDResponse) GetNamespace() gopenid.NamespaceURI {
	return res.message.GetOpenIDNamespace()
}

func (res *openIDResponse) AddArg(key gopenid.MessageKey, value gopenid.MessageValue) {
	res.message.AddArg(key, value)
}

func (res *openIDResponse) GetArg(key gopenid.MessageKey) (gopenid.MessageValue, bool) {
	return res.message.GetArg(key)
}

func (res *openIDResponse) GetMessage() gopenid.Message {
	return res.message
}

func (res *openIDResponse) NeedsRedirect() bool {
	return res.needsRedirect
}

func (res *openIDResponse) IsPermanently() bool {
	return res.isPermanently
}

func (res *openIDResponse) GetRedirectTo() string {
	redirectTo, _ := url.Parse(res.returnTo)
	query := redirectTo.Query()

	for k, v := range res.message.ToQuery() {
		query[k] = v
	}

	redirectTo.RawQuery = query.Encode()
	return redirectTo.String()
}

func (res *openIDResponse) GetBody() []byte {
	kv, _ := res.message.ToKeyValue(res.message.Keys())
	return kv
}

func (res *openIDResponse) GetContentType() string {
	return res.contentType
}

type yadisResponse struct {
	et *gopenid.XRDSDocument
}

func newYadisResponse(et *gopenid.XRDSDocument) *yadisResponse {
	return &yadisResponse{
		et: et,
	}
}

func (res *yadisResponse) NeedsRedirect() bool {
	return false
}

func (res *yadisResponse) IsPermanently() bool {
	return false
}

func (res *yadisResponse) GetRedirectTo() string {
	return ""
}

func (res *yadisResponse) GetBody() (b []byte) {
	b, _ = gopenid.EncodeXRDS(res.et)
	return
}

func (res *yadisResponse) GetContentType() string {
	return "application/xrds+xml"
}
