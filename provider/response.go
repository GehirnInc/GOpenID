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

type OpenIDResponse struct {
	request       Request
	message       gopenid.Message
	needsRedirect bool
	isPermanently bool
	contentType   string
	returnTo      string
}

func NewOpenIDResponse(req Request) *OpenIDResponse {
	res := &OpenIDResponse{
		request: req,
		message: gopenid.NewMessage(req.GetNamespace()),
	}

	switch ret := req.(type) {
	case *CheckIDRequest:
		res.needsRedirect = true
		res.isPermanently = false

		returnTo, _ := ret.message.GetArg(gopenid.NewMessageKey(ret.GetNamespace(), "return_to"))
		res.returnTo = returnTo.String()
	case *AssociateRequest:
		res.needsRedirect = false
		res.contentType = "text/plain;charset=utf8"
	case *CheckAuthenticationRequest:
		res.needsRedirect = false
		res.contentType = "text/plain;charset=utf8"
	}

	return res
}

func (res *OpenIDResponse) GetNamespace() gopenid.NamespaceURI {
	return res.message.GetOpenIDNamespace()
}

func (res *OpenIDResponse) AddArg(key gopenid.MessageKey, value gopenid.MessageValue) {
	res.message.AddArg(key, value)
}

func (res *OpenIDResponse) GetArg(key gopenid.MessageKey) (gopenid.MessageValue, bool) {
	return res.message.GetArg(key)
}

func (res *OpenIDResponse) GetMessage() gopenid.Message {
	return res.message
}

func (res *OpenIDResponse) NeedsRedirect() bool {
	return res.needsRedirect
}

func (res *OpenIDResponse) IsPermanently() bool {
	return res.isPermanently
}

func (res *OpenIDResponse) GetRedirectTo() string {
	redirectTo, _ := url.Parse(res.returnTo)
	query := redirectTo.Query()

	for k, v := range res.message.ToQuery() {
		query[k] = v
	}

	redirectTo.RawQuery = query.Encode()
	return redirectTo.String()
}

func (res *OpenIDResponse) GetBody() []byte {
	kv, _ := res.message.ToKeyValue(res.message.Keys())
	return kv
}

func (res *OpenIDResponse) GetContentType() string {
	return res.contentType
}

type YadisResponse struct {
	et *gopenid.XRDSDocument
}

func NewYadisResponse(et *gopenid.XRDSDocument) *YadisResponse {
	return &YadisResponse{
		et: et,
	}
}

func (res *YadisResponse) NeedsRedirect() bool {
	return false
}

func (res *YadisResponse) IsPermanently() bool {
	return false
}

func (res *YadisResponse) GetRedirectTo() string {
	return ""
}

func (res *YadisResponse) GetBody() (b []byte) {
	b, _ = gopenid.EncodeXRDS(res.et)
	return
}

func (res *YadisResponse) GetContentType() string {
	return "application/xrds+xml"
}
