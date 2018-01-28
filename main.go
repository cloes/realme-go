package main

import (
	"encoding/xml"
	"fmt"
	"os"
)

func main() {
	fmt.Println("hello world")

	/*
		authnrequest, err := ioutil.ReadFile("authnrequest.txt")
		if err != nil {
			fmt.Print(err)
		}
	*/

	type Issuer struct {
		XMLName     xml.Name `xml:"saml:Issuer"`
		IssuerValue string   `xml:",chardata"`
	}

	type NameIDPolicy struct {
		XMLName     xml.Name `xml:"samlp:NameIDPolicy"`
		AllowCreate string   `xml:"AllowCreate,attr"`
		Format      string   `xml:"Format,attr"`
	}

	type Authnrequest struct {
		XMLName                       xml.Name `xml:"samlp:AuthnRequest"`
		xmlnsSaml                     string   `xml:"xmlns:saml,attr"`
		xmlnsSamlp                    string   `xml:"xmlns:samlp,attr"`
		AssertionConsumerServiceIndex string   `xml:"AssertionConsumerServiceIndex,attr"`
		Destination                   string   `xml:"Destination,attr"`
		ID                            string   `xml:"ID,attr"`
		IssueInstant                  string   `xml:"IssueInstant,attr"`
		ProviderName                  string   `xml:"ProviderName,attr"`
		Version                       string   `xml:"Version,attr"`
		Issuer                        Issuer
		NameIDPolicy                  NameIDPolicy
		AllowCreate                   string `xml:"samlp:NameIDPolicy,aa,attr"`
		Format                        string `xml:"Format,attr"`
	}

	var auth Authnrequest
	var issuer Issuer
	var nameIDPolicy NameIDPolicy

	issuer.IssuerValue = "http://myrealme.test/mts2/sp"

	nameIDPolicy.AllowCreate = "true"
	nameIDPolicy.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	auth.xmlnsSaml = "urn:oasis:names:tc:SAML:2.0:assertion"
	auth.xmlnsSamlp = "urn:oasis:names:tc:SAML:2.0:protocol"
	auth.AssertionConsumerServiceIndex = "0"
	auth.Destination = "https://mts.realme.govt.nz/logon-mts/mtsEntryPoint"
	auth.ID = "a958a20e059c26d1cfb73163b1a6c4f9"
	auth.IssueInstant = "2018.01.01"
	auth.ProviderName = "http://myrealme.test/mts2/sp"
	auth.Version = "2.0"
	auth.Issuer = issuer
	auth.NameIDPolicy = nameIDPolicy
	//auth.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	tmp, err := xml.MarshalIndent(auth, "  ", "    ")

	//err := xml.Unmarshal([]byte(data), &v)
	if err != nil {
		fmt.Print(err)
	}

	os.Stdout.Write(tmp)

	//fmt.Printf("Groups: %v\n", v.Groups)

}
