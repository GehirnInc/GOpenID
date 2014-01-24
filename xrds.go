package gopenid

import (
	"bytes"
	"encoding/xml"
)

const (
	NsOpenID20Server NamespaceURI = "http://specs.openid.net/auth/2.0/server"
	NsOpenID20Signon NamespaceURI = "http://specs.openid.net/auth/2.0/signon"

	NsXRDS  NamespaceURI = "xri://$xrds"
	NsXRD20 NamespaceURI = "xri://$xrd*($v*2.0)"
)

type XRDSDocument struct {
	XMLName xml.Name `xml:"xri://$xrds XRDS"`
	XRD     XRDSXRDElement
}

type XRDSXRDElement struct {
	XMLName  xml.Name `xml:"xri://$xrd*($v*2.0) XRD"`
	Services []XRDSServiceElement
}

type XRDSServiceElement struct {
	XMLName  xml.Name `xml:"xri://$xrd*($v*2.0) Service"`
	Priority int      `xml:"priority,attr"`
	Type     []string `xml:"Type"`
	URI      string   `xml:"URI"`
	LocalID  string   `xml:"LocalID,omitempty"`
}

func EncodeXRDS(et *XRDSDocument) ([]byte, error) {
	b := bytes.NewBufferString(xml.Header)

	e := xml.NewEncoder(b)
	e.Indent("", "    ")
	if err := e.Encode(et); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
