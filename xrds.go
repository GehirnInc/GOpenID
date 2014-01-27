package gopenid

import (
	"bytes"
	"encoding/xml"
)

const (
	NsOpenID20Server NamespaceURI = "http://specs.openid.net/auth/2.0/server" // OpenID 2.0 Server.
	NsOpenID20Signon NamespaceURI = "http://specs.openid.net/auth/2.0/signon" // OpenID 2.0 Signon.

	NsXRDS  NamespaceURI = "xri://$xrds"         // Namespace for generic XRDS.
	NsXRD20 NamespaceURI = "xri://$xrd*($v*2.0)" // Namespace for XRDS version 2.0.
)

// XRDSDocument represents XRDS Document.
type XRDSDocument struct {
	XMLName xml.Name `xml:"xri://$xrds XRDS"`
	XRD     XRDSXRDElement
}

// XRDSXRDElement represents XRD node tree in XRDS document.
type XRDSXRDElement struct {
	XMLName  xml.Name `xml:"xri://$xrd*($v*2.0) XRD"`
	Services []XRDSServiceElement
}

// XRDSServiceElement represents Service node in XRDS document.
type XRDSServiceElement struct {
	XMLName  xml.Name `xml:"xri://$xrd*($v*2.0) Service"`
	Priority int      `xml:"priority,attr"`
	Type     []string `xml:"Type"`
	URI      string   `xml:"URI"`
	LocalID  string   `xml:"LocalID,omitempty"`
}

// EncodeXRDS returns et as XML document.
func EncodeXRDS(et *XRDSDocument) ([]byte, error) {
	b := bytes.NewBufferString(xml.Header)

	e := xml.NewEncoder(b)
	e.Indent("", "    ")
	if err := e.Encode(et); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
