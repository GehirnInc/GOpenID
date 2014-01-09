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

	NsIdentifierSelect NamespaceURI = "http://specs.openid.net/auth/2.0/identifier_select"
)

var (
	ErrMalformedMessage   = errors.New("malformed Message")
	ErrUnsupportedVersion = errors.New("unsupported version")

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
	namespace     NamespaceURI
	nsuri2nsalias map[NamespaceURI]string
	nsalias2nsuri map[string]NamespaceURI
	args          map[MessageKey]MessageValue
}

func NewMessage(ns NamespaceURI) Message {
	return Message{
		namespace:     ns,
		nsuri2nsalias: make(map[NamespaceURI]string),
		nsalias2nsuri: make(map[string]NamespaceURI),
		args:          make(map[MessageKey]MessageValue),
	}
}

func (m *Message) GetOpenIDNamespace() NamespaceURI {
	return m.namespace
}

func (m *Message) GetNamespaceURI(alias string) (NamespaceURI, bool) {
	if alias == "openid" {
		return m.GetOpenIDNamespace(), true
	} else {
		nsuri, ok := m.nsalias2nsuri[alias]
		return nsuri, ok
	}
}

func (m *Message) GetNamespaceAlias(uri NamespaceURI) (string, bool) {
	if uri == m.GetOpenIDNamespace() {
		return "", true
	} else {
		nsalias, ok := m.nsuri2nsalias[uri]
		return nsalias, ok
	}
}

func (m *Message) SetNamespaceAlias(alias string, uri NamespaceURI) {
	m.nsuri2nsalias[uri] = alias
	m.nsalias2nsuri[alias] = uri
}

func (m *Message) GetArg(k MessageKey) (MessageValue, bool) {
	v, ok := m.args[k]
	return v, ok
}

func (m *Message) AddArg(k MessageKey, v MessageValue) {
	m.args[k] = v
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

func (m *Message) ToQuery() url.Values {
	query := url.Values{
		"openid.ns": []string{m.namespace.String()},
	}

	for nsalias, nsuri := range m.nsalias2nsuri {
		query[fmt.Sprintf("openid.ns.%s", nsalias)] = []string{nsuri.String()}
	}

	for key, value := range m.args {
		var queryKey string
		if alias, _ := m.GetNamespaceAlias(key.GetNamespace()); alias == "" {
			queryKey = fmt.Sprintf("openid.%s", key.GetKey())
		} else {
			queryKey = fmt.Sprintf("openid.%s.%s", alias, key.GetKey())
		}
		query[queryKey] = []string{value.String()}
	}

	return query
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
		err = ErrUnsupportedVersion
		return
	}

	if ns == "" {
		// OpenID Authentication 1.1 Compatibility mode
		ns = NsOpenID11
	}

	msg = NewMessage(ns)
	for nsalias, kv := range args {
		nsuri, isKnownAlias := nsmap[nsalias]
		if isKnownAlias {
			msg.SetNamespaceAlias(nsalias, nsuri)
		} else {
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
