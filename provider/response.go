package provider

import (
	"github.com/GehirnInc/GOpenID"
	"net/url"
)

type Response struct {
	request       Request
	message       gopenid.Message
	needsRedirect bool
	isPermanently bool
	contentType   string
	returnTo      string
}

func NewResponse(req Request) (res *Response) {
	res = &Response{
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

	return
}

func (res *Response) GetNamespace() gopenid.NamespaceURI {
	return res.message.GetOpenIDNamespace()
}

func (res *Response) AddArg(key gopenid.MessageKey, value gopenid.MessageValue) {
	res.message.AddArg(key, value)
}

func (res *Response) GetArg(key gopenid.MessageKey) (gopenid.MessageValue, bool) {
	return res.message.GetArg(key)
}

func (res *Response) GetMessage() gopenid.Message {
	return res.message
}

func (res *Response) NeedsRedirect() bool {
	return res.needsRedirect
}

func (res *Response) IsPermanently() bool {
	return res.isPermanently
}

func (res *Response) GetRedirectTo() string {
	redirectTo, _ := url.Parse(res.returnTo)
	query := redirectTo.Query()

	for k, v := range res.message.ToQuery() {
		query[k] = v
	}

	redirectTo.RawQuery = query.Encode()
	return redirectTo.String()
}

func (res *Response) GetBody() []byte {
	kv, _ := res.message.ToKeyValue(res.message.Keys())
	return kv
}

func (res *Response) GetContentType() string {
	return res.contentType
}
