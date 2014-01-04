package gopenid

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	NsOpenID10 NamespaceURI = "http://openid.net/signon/1.0"
	NsOpenID11 NamespaceURI = "http://openid.net/signon/1.1"
	NsOpenID20 NamespaceURI = "http://specs.openid.net/auth/2.0"
)

var (
	ErrMalformedMessage = errors.New("malformed Message")

	ProtocolFields = []string{
		"assoc_handle",
		"assoc_type",
		"claimed_id",
		"contact",
		"delegate",
		"dh_consumer_public",
		"dh_gen",
		"dh_modulus",
		"error",
		"identity",
		"invalidate_handle",
		"mode",
		"ns",
		"op_endpoint",
		"openid",
		"realm",
		"reference",
		"response_nonce",
		"return_to",
		"server",
		"session_type",
		"sig",
		"signed",
		"trust_root",
	}
)

type NamespaceURI string

func (ns NamespaceURI) String() string {
	return string(ns)
}

type MessageKey struct {
	namespace NamespaceURI
	key       string
}

func NewMessageKey(ns NamespaceURI, key string) MessageKey {
	return MessageKey{
		namespace: ns,
		key:       key,
	}
}

func (k *MessageKey) GetNamespace() NamespaceURI {
	return k.namespace
}

func (k *MessageKey) GetKey() string {
	return k.key
}

type MessageValue string

func (v MessageValue) String() string {
	return string(v)
}

type Message struct {
	namespace NamespaceURI
	args      map[MessageKey]MessageValue
}

func NewMessage(ns NamespaceURI) Message {
	return Message{
		namespace: ns,
		args:      make(map[MessageKey]MessageValue),
	}
}

func (m *Message) setNamespace(ns NamespaceURI) {
	m.namespace = ns
}

func (m *Message) GetNamespace() NamespaceURI {
	return m.namespace
}

func (m *Message) AddArg(k MessageKey, v MessageValue) {
	m.args[k] = v
}

func (m *Message) GetArg(k MessageKey) (MessageValue, bool) {
	v, ok := m.args[k]
	return v, ok
}

func (m *Message) GetArgs(nsuri NamespaceURI) map[MessageKey]MessageValue {
	ret := make(map[MessageKey]MessageValue)

	for k, v := range m.args {
		if k.GetNamespace() == nsuri {
			ret[k] = v
		}
	}
	return ret
}

func MessageFromQuery(req url.Values) (msg Message, err error) {
	var (
		ns    NamespaceURI
		nsmap = make(map[string]NamespaceURI)
		args  = make(map[string]map[string]string)
	)

	for key, values := range req {
		if len(values) > 1 {
			// Messages MUST NOT contain multiple parameters with the same name
			err = ErrMalformedMessage
			return
		} else if !strings.HasPrefix(key, "openid.") {
			continue
		}

		var (
			parts = strings.SplitN(key[7:], ".", 2)
			value = values[0]

			nsalias string
			key     string
		)

		if len(parts) == 1 {
			key = parts[0]
		} else {
			nsalias = parts[0]
			key = parts[1]
		}

		if nsalias == "" && key == "ns" {
			ns = NamespaceURI(value)
		} else if nsalias == "ns" {
			if strings.Index(key, ".") >= 0 {
				// A namespace alias MUST NOT contain a period
				err = ErrMalformedMessage
				return
			} else if idx := sort.SearchStrings(ProtocolFields, key); ProtocolFields[idx] == key {
				// The namespace alias is not allowed
				err = ErrMalformedMessage
				return
			}
			nsmap[key] = NamespaceURI(value)
		} else {
			if _, ok := args[nsalias]; !ok {
				args[nsalias] = make(map[string]string)
			}
			args[nsalias][key] = value
		}
	}

	switch ns {
	case NsOpenID10:
	case NsOpenID11:
	case NsOpenID20:
	case "":
	default:
		// TODO: return error
		// unsuported version
	}

	if ns == "" {
		// OpenID Authentication 1.1 Compatibility mode
		ns = NsOpenID11
	}

	msg = NewMessage(ns)
	for nsalias, kv := range args {
		nsuri, isKnownAlias := nsmap[nsalias]
		if !isKnownAlias {
			nsuri = ns
		}

		for key, value := range kv {
			if !isKnownAlias && nsalias != "" {
				key = fmt.Sprintf("%s.%s", nsalias, key)
			}

			msg.AddArg(
				NewMessageKey(nsuri, key),
				MessageValue(value),
			)
		}
	}

	return
}
