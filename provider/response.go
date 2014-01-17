package provider

import (
	"github.com/GehirnInc/GOpenID"
)

type Response struct {
	request Request
	message gopenid.Message
}

func NewResponse(ns gopenid.NamespaceURI) *Response {
	return &Response{
		message: gopenid.NewMessage(ns),
	}
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
