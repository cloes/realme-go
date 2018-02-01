package main

import (
	"fmt"
	"encoding/xml"
	//"io/ioutil"
	"bytes"
	"io"
	"strings"
	"encoding/base64"
	"net/url"
	"time"
	"github.com/satori/go.uuid"
	"compress/flate"
	"encoding/pem"
	"crypto/x509"
	"crypto"
	"crypto/rsa"
	"os"
	"io/ioutil"
)

const (
	DSAwithSHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
	RSAwithSHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	idpUrl = "https://mts.realme.govt.nz/logon-mts/mtsEntryPoint?"
)


//生成字符串格式的authnrequest
func getAuthnrequestXML() string{
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

	issueInstant := time.Now().UTC().Format(time.RFC3339)
	id, err := uuid.NewV4()
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}

	idString := strings.Replace(id.String(), "-", "", -1)
	idString = "a" + idString[1:]

	issuer.IssuerValue = "http://myrealme.test/mts2/sp"

	nameIDPolicy.AllowCreate = "true"
	nameIDPolicy.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	auth.Saml = "urn:oasis:names:tc:SAML:2.0:assertion"
	auth.Samlp = "urn:oasis:names:tc:SAML:2.0:protocol"
	auth.AssertionConsumerServiceIndex = "0"
	auth.Destination = "https://mts.realme.govt.nz/logon-mts/mtsEntryPoint"
	auth.ID = idString
	auth.IssueInstant = issueInstant
	auth.ProviderName = "http://myrealme.test/mts2/sp"
	auth.Version = "2.0"
	auth.Issuer = issuer
	auth.NameIDPolicy = nameIDPolicy

	authnContextClassRef.AuthnContextClassRefValue = "urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength"
	requestedAuthnContext.AuthnContextClassRef = authnContextClassRef

	auth.RequestedAuthnContext = requestedAuthnContext

	tmp, err := xml.MarshalIndent(auth, "", "  ")
	return string(tmp)
}


func defalte(authnrequestXML string) string{
	var deflateResult bytes.Buffer
	flateWriter,err := flate.NewWriter(&deflateResult,flate.DefaultCompression)
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}

	io.Copy(flateWriter,strings.NewReader(authnrequestXML))

	flateWriter.Close()
	return deflateResult.String()
}


func getSAMLRequestString() string{
	authnrequestXML := getAuthnrequestXML()
	deflateResult := defalte(authnrequestXML)

	//err := xml.Unmarshal([]byte(data), &v)
	//os.Stdout.Write(tmp)
	//ioutil.WriteFile("./output.txt", tmp, 0666)
	//fmt.Printf("Groups: %v\n", v.Groups)

	baseEncondedContent := base64.StdEncoding.EncodeToString([]byte(deflateResult))

	QueryEscapedContent := url.QueryEscape(baseEncondedContent)
	SAMLRequestResult := "SAMLRequest=" + QueryEscapedContent
	return SAMLRequestResult
}

func getSigAlgString(sigAlg string) string{
	var sigAlgString string
	if sigAlg == "dsa-sha1" {
		sigAlgString = "SigAlg=" + url.QueryEscape(DSAwithSHA1)
	}else if sigAlg == "rsa-sha1" {
		sigAlgString = "SigAlg=" + url.QueryEscape(RSAwithSHA1)
	}
	return sigAlgString
}

func getSignatureString(contentForSign string) string{
	privateKey,_ := ioutil.ReadFile("mts_saml_sp.pem")
	block, _ := pem.Decode(privateKey)
	if block == nil {       // 失败情况
		fmt.Print("get pem file fail")
	}

	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Print("get pem file fail2")
	}

	h := crypto.Hash.New(crypto.SHA1)
	h.Write([]byte(contentForSign))
	hashed := h.Sum(nil)

	// 进行rsa加密签名
	signedData, err := rsa.SignPKCS1v15(nil, private.(*rsa.PrivateKey), crypto.SHA1, hashed)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
	}

	baseEncodedData := base64.StdEncoding.EncodeToString(signedData)
	urlEncodedData := url.QueryEscape(baseEncodedData)

	return "Signature=" + urlEncodedData
}

func GetQueryString(sigAlg string,relayState string) string{
	var contentForSign string
	SAMLRequestString := getSAMLRequestString()
	sigAlgString := getSigAlgString(sigAlg)

	if relayState != "" {
		contentForSign = SAMLRequestString + "&" + "relayState=" + relayState + "&" + sigAlgString
	}else {
		contentForSign = SAMLRequestString + "&" + sigAlgString
	}

	signatureString := getSignatureString(contentForSign)

	result := contentForSign + "&" + signatureString
	return idpUrl + result

}