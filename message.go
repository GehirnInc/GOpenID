package gopenid

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

const (
	NsOpenID10 NamespaceURI = "http://openid.net/signon/1.0"     // Namespace for OpenID 1.0
	NsOpenID11 NamespaceURI = "http://openid.net/signon/1.1"     // Namespace for OpenID 1.1
	NsOpenID20 NamespaceURI = "http://specs.openid.net/auth/2.0" // Namespace for OpenID 2.0

	NsIdentifierSelect NamespaceURI = "http://specs.openid.net/auth/2.0/identifier_select"
)

var (
	ErrMalformedMessage   = errors.New("malformed Message")
	ErrUnsupportedVersion = errors.New("unsupported version")
	ErrKeyContainsColon   = errors.New("key contains colon")
	ErrKeyContainsNewLine = errors.New("key contains new line")
	ErrValueNotFound      = errors.New("value not found")

	protocolFields = []string{
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

// NamespaceURI represents URI for Namespace.
type NamespaceURI string

// String returns as string.
func (ns NamespaceURI) String() string {
	return string(ns)
}

// MessageKey is a key of Message.
type MessageKey struct {
	namespace NamespaceURI
	key       string
}

// NewMessageKey returns a new MessageKey given NamespaceURI, and key.
func NewMessageKey(ns NamespaceURI, key string) MessageKey {
	return MessageKey{
		namespace: ns,
		key:       key,
	}
}

// GetNamespace returns NamespaceURI of k.
func (k *MessageKey) GetNamespace() NamespaceURI {
	return k.namespace
}

// GetKey returns key of k.
func (k *MessageKey) GetKey() string {
	return k.key
}

// MessageValue is a value of Message.
type MessageValue string

// String returns v as string.
func (v MessageValue) String() string {
	return string(v)
}

// Bytes returns v as []byte.
func (v MessageValue) Bytes() []byte {
	return []byte(v)
}

// Message represents OpenID protocol message.
type Message struct {
	namespace     NamespaceURI
	nsuri2nsalias map[NamespaceURI]string
	nsalias2nsuri map[string]NamespaceURI
	args          map[MessageKey]MessageValue
	sync.Mutex
}

// NewMessage returns a new Message with the given NamespaceURI.
func NewMessage(ns NamespaceURI) Message {
	return Message{
		namespace:     ns,
		nsuri2nsalias: make(map[NamespaceURI]string),
		nsalias2nsuri: make(map[string]NamespaceURI),
		args:          make(map[MessageKey]MessageValue),
	}
}

// GetOpenIDNamespace returns NamespaceURI of m.
func (m *Message) GetOpenIDNamespace() NamespaceURI {
	return m.namespace
}

// GetNamespaceURI returns NamespaceURI mapped to the given alias.
// If NamespaceURI does not exist, GetNamespaceURI returns false as 2nd return value.
func (m *Message) GetNamespaceURI(alias string) (NamespaceURI, bool) {
	if alias == "openid" {
		return m.GetOpenIDNamespace(), true
	}

	nsuri, ok := m.nsalias2nsuri[alias]
	return nsuri, ok
}

// GetNamespaceAlias returns alias is pointing to the given NamespaceURI.
// If alias does not exist, GetNamespaceURI returns false as 2nd return value.
func (m *Message) GetNamespaceAlias(uri NamespaceURI) (string, bool) {
	if uri == m.GetOpenIDNamespace() {
		return "", true
	}

	nsalias, ok := m.nsuri2nsalias[uri]
	return nsalias, ok
}

// SetNamespaceAlias is a function to register relationship between alias and NamespaceURI.
func (m *Message) SetNamespaceAlias(alias string, uri NamespaceURI) {
	m.nsuri2nsalias[uri] = alias
	m.nsalias2nsuri[alias] = uri
}

// GetArg returns value of given k.
// If value does not exist, GetArg returns false as 2nd return value.
func (m *Message) GetArg(k MessageKey) (MessageValue, bool) {
	v, ok := m.args[k]
	return v, ok
}

// AddArg registers given the v as value of k.
func (m *Message) AddArg(k MessageKey, v MessageValue) {
	m.args[k] = v
}

// GetArgs returns the subset of m as map[MessageKey]MessageValue.
// Returned subset contains values related to the given NamespaceURI.
func (m *Message) GetArgs(nsuri NamespaceURI) map[MessageKey]MessageValue {
	ret := make(map[MessageKey]MessageValue)

	for k, v := range m.args {
		if k.GetNamespace() == nsuri {
			ret[k] = v
		}
	}
	return ret
}

// ToQuery returns the m as url.Values.
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

// Keys returns all of keys m has.
func (m *Message) Keys() []string {
	ret := make([]string, 1, len(m.args)+1)
	ret[0] = "openid.ns"

	for key := range m.args {
		parts := make([]string, 0, 3)
		parts = append(parts, "openid")

		if nsalias, ok := m.GetNamespaceAlias(key.GetNamespace()); !ok {
			continue
		} else if nsalias != "" {
			parts = append(parts, nsalias)
		}

		parts = append(parts, key.GetKey())

		ret = append(
			ret,
			strings.Join(parts, "."),
		)
	}

	return ret

}

// ToKeyValue returns part of m as KeyValue format.
// Returnd KeyValue follows the given order.
func (m *Message) ToKeyValue(order []string) (b []byte, err error) {
	validator := func(str string, isKey bool) error {
		if isKey && strings.Index(str, ":") > -1 {
			return ErrKeyContainsColon
		}

		if strings.Index(str, "\n") > -1 {
			return ErrKeyContainsNewLine
		}

		return nil
	}

	lines := make([][]byte, 0, len(order)+1)

	for _, key := range order {
		if !strings.HasPrefix(key, "openid.") {
			err = ErrValueNotFound
			return
		}
		key = key[7:]

		var (
			parts = strings.SplitN(key, ".", 2)
			value string
		)
		if len(parts) > 1 {
			if parts[0] == "ns" {
				v, ok := m.nsalias2nsuri[parts[1]]
				if !ok {
					err = ErrValueNotFound
					return
				}
				value = v.String()
			} else {
				v, ok := m.args[NewMessageKey(m.nsalias2nsuri[parts[0]], parts[1])]
				if !ok {
					err = ErrValueNotFound
					return
				}
				value = v.String()
			}
		} else if parts[0] == "ns" {
			value = m.namespace.String()
		} else {
			v, ok := m.args[NewMessageKey(m.namespace, parts[0])]
			if !ok {
				err = ErrValueNotFound
				return
			}
			value = v.String()
		}

		if err = validator(key, true); err != nil {
			return
		} else if err = validator(value, false); err != nil {
			return
		}

		lines = append(
			lines,
			[]byte(fmt.Sprintf("%s:%s", key, value)),
		)
	}
	lines = append(lines, nil)
	b = bytes.Join(lines, []byte{'\n'})

	return
}

// Copy returns copy of m.
func (m *Message) Copy() Message {
	m.Lock()
	defer m.Unlock()

	msg := NewMessage(m.namespace)

	for k, v := range m.nsuri2nsalias {
		msg.nsuri2nsalias[k] = v
	}

	for k, v := range m.nsalias2nsuri {
		msg.nsalias2nsuri[k] = v
	}

	for k, v := range m.args {
		msg.args[k] = v
	}

	return msg
}

// MessageFromQuery returns a new message as a result of parsing the given query.
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
			} else if idx := sort.SearchStrings(protocolFields, key); protocolFields[idx] == key {
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
