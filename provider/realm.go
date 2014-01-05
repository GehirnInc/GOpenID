package provider

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrMalformedRealm = errors.New("malformed realm")
)

type Realm struct {
	Scheme   string
	Host     string
	Port     string
	Path     string
	RawQuery string
	Wildcard bool
}

func ParseRealm(rawurl string) (realm Realm, err error) {
	// var parsed *net.URL
	parsed, err := url.Parse(rawurl)
	if err != nil {
		err = ErrMalformedRealm
		return
	}

	if !(parsed.Scheme == "http" || parsed.Scheme == "https") {
		err = ErrMalformedRealm
		return
	}

	var (
		host     = parsed.Host
		port     string
		wildcard bool
	)
	if idx := strings.Index(host, ":"); idx > -1 {
		port = host[idx+1:]
		host = host[0:idx]
		if portInt, err := strconv.Atoi(port); err != nil {
			err = ErrMalformedRealm
		} else if (parsed.Scheme == "http" && portInt == 80) || (parsed.Scheme == "https" && portInt == 443) {
			port = ""
		}
	}

	if idx := strings.Index(host, "*"); idx == 0 {
		if len(host) < 2 || host[1] != '.' {
			err = ErrMalformedRealm
			return
		} else if strings.Count(host, "*") > 1 {
			err = ErrMalformedRealm
			return
		}
		host = host[1:]
		wildcard = true
	} else if idx > 0 {
		err = ErrMalformedRealm
		return
	}

	if parsed.Fragment != "" {
		err = ErrMalformedRealm
		return
	}

	if queryLen := len(parsed.RawQuery); queryLen > 0 && parsed.RawQuery[queryLen-1] == '&' {
		parsed.RawQuery = parsed.RawQuery[:queryLen-1]
	}

	realm = Realm{
		Scheme:   parsed.Scheme,
		Host:     host,
		Port:     port,
		Path:     parsed.Path,
		RawQuery: parsed.RawQuery,
		Wildcard: wildcard,
	}
	return
}

func (realm *Realm) Validate(rawurl string) bool {
	if idx := strings.Index(rawurl, "#"); idx > -1 {
		rawurl = rawurl[0:idx]
	}

	parsed, err := ParseRealm(rawurl)
	if err != nil {
		return false
	}

	// validate scheme
	if parsed.Scheme != realm.Scheme {
		return false
	}

	// validate host
	if parsed.Wildcard {
		return false
	} else if realm.Wildcard {
		if !strings.HasSuffix(parsed.Host, realm.Host[1:]) {
			return false
		}
	} else if realm.Host != parsed.Host {
		return false
	}

	// validate port
	if parsed.Port != realm.Port {
		return false
	}

	// validate path and query
	if parsed.Path == realm.Path {
		if parsed.RawQuery != realm.RawQuery {
			if queryLen := len(realm.RawQuery); len(parsed.RawQuery) < queryLen {
				return false
			} else if queryLen > 0 {
				if parsed.RawQuery[:queryLen] != realm.RawQuery {
					return false
				} else if parsed.RawQuery[queryLen] != '&' {
					// ex realm ?foo=bar, rawurl ?foo=barbaz
					return false
				}
			}
		}
	} else {
		if realm.RawQuery != "" {
			return false
		} else if pathLen := len(realm.Path); len(parsed.Path) < pathLen {
			return false
		} else if pathLen > 0 {
			if parsed.Path[:pathLen] != realm.Path {
				return false
			} else if realm.Path[pathLen-1] != '/' && parsed.Path[pathLen] != '/' {
				// ex realm: /abc, rawurl /abcd
				return false
			}
		}
	}

	return true
}
