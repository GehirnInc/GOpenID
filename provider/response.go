package provider

import (
	"github.com/GehirnInc/GOpenID"
)

type Response struct {
	request Request
	message gopenid.Message
}

func NewResponse(req Request) *Response {
	return &Response{
		request: req,
		message: gopenid.NewMessage(req.GetNamespace()),
	}
}

func (res *Response) AddArg(key gopenid.MessageKey, value gopenid.MessageValue) {
	res.message.AddArg(key, value)
}

func (res *Response) GetArg(key gopenid.MessageKey) (gopenid.MessageValue, bool) {
	return res.message.GetArg(key)
}

func (res *Response) NeedsSigning() bool {
	mode, _ := res.message.GetArg(
		gopenid.NewMessageKey(res.message.GetOpenIDNamespace(), "mode"),
	)

	return mode == "id_res"
}
