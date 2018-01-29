package main

import (
	"encoding/xml"
	"fmt"
	"os"
)

func main() {
	type Issuer struct {
		XMLName     xml.Name `xml:"saml:Issuer"`
		IssuerValue string   `xml:",chardata"`
	}

	type NameIDPolicy struct {
		XMLName     xml.Name `xml:"samlp:NameIDPolicy"`
		AllowCreate string   `xml:"AllowCreate,attr"`
		Format      string   `xml:"Format,attr"`
	}

	type AuthnContextClassRef struct {
		XMLName                   xml.Name `xml:"saml:AuthnContextClassRef"`
		AuthnContextClassRefValue string   `xml:",chardata"`
	}

	type RequestedAuthnContext struct {
		XMLName              xml.Name `xml:"samlp:RequestedAuthnContext"`
		AuthnContextClassRef AuthnContextClassRef
	}

	type Authnrequest struct {
		XMLName                       xml.Name `xml:"samlp:AuthnRequest"`
		Saml                          string   `xml:"xmlns:saml,attr"`
		Samlp                         string   `xml:"xmlns:samlp,attr"`
		AssertionConsumerServiceIndex string   `xml:"AssertionConsumerServiceIndex,attr"`
		Destination                   string   `xml:"Destination,attr"`
		ID                            string   `xml:"ID,attr"`
		IssueInstant                  string   `xml:"IssueInstant,attr"`
		ProviderName                  string   `xml:"ProviderName,attr"`
		Version                       string   `xml:"Version,attr"`
		Issuer                        Issuer
		NameIDPolicy                  NameIDPolicy
		RequestedAuthnContext         RequestedAuthnContext
		//AllowCreate                   string `xml:"samlp:NameIDPolicy,aa,attr"`
		//Format                        string `xml:"Format,attr"`
	}

	var auth Authnrequest
	var issuer Issuer
	var nameIDPolicy NameIDPolicy

	var requestedAuthnContext RequestedAuthnContext
	var authnContextClassRef AuthnContextClassRef

	issuer.IssuerValue = "http://myrealme.test/mts2/sp"

	nameIDPolicy.AllowCreate = "true"
	nameIDPolicy.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	auth.Saml = "urn:oasis:names:tc:SAML:2.0:assertion"
	auth.Samlp = "urn:oasis:names:tc:SAML:2.0:protocol"
	auth.AssertionConsumerServiceIndex = "0"
	auth.Destination = "https://mts.realme.govt.nz/logon-mts/mtsEntryPoint"
	auth.ID = "a958a20e059c26d1cfb73163b1a6c4f9"
	auth.IssueInstant = "2018.01.01"
	auth.ProviderName = "http://myrealme.test/mts2/sp"
	auth.Version = "2.0"
	auth.Issuer = issuer
	auth.NameIDPolicy = nameIDPolicy

	authnContextClassRef.AuthnContextClassRefValue = "urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength"
	requestedAuthnContext.AuthnContextClassRef = authnContextClassRef

	auth.RequestedAuthnContext = requestedAuthnContext

	//auth.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	tmp, err := xml.MarshalIndent(auth, "", "  ")

	//err := xml.Unmarshal([]byte(data), &v)
	if err != nil {
		fmt.Print(err)
	}

	os.Stdout.Write(tmp)

	//ioutil.WriteFile("./output.txt", tmp, 0666)

	//fmt.Printf("Groups: %v\n", v.Groups)

}
