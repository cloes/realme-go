package RealmeGOSDK

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	"github.com/satori/go.uuid"
)

const (
	DSAwithSHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
	RSAwithSHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	idpUrl      = "https://mts.realme.govt.nz/logon-mts/mtsEntryPoint?"
)

type ServiceProvider struct {
	SigAlg             string //dsa-sha1 or rsa-sha1
	Issuer             string //"http://myrealme.test/mts2/sp"
	ProviderName       string //"http://myrealme.test/mts2/sp"
	RelayState         string
	PrivateKeyFilePath string
}

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

type AuthnRequest struct {
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

//GetQueryString return realme AuthnRequest
func (sp *ServiceProvider) GetQueryString() (string, error) {
	var contentForSign string
	SAMLRequestString, err := sp.getSAMLRequestString()
	if err != nil {
		return "", err
	}

	sigAlgString := getSigAlgString(sp.SigAlg)
	if sp.RelayState != "" {
		contentForSign = SAMLRequestString + "&" + "relayState=" + sp.RelayState + "&" + sigAlgString
	} else {
		contentForSign = SAMLRequestString + "&" + sigAlgString
	}

	signatureString, err := sp.getSignatureString(contentForSign)
	if err != nil {
		return "", err
	}

	result := contentForSign + "&" + signatureString
	return idpUrl + result, nil
}

func (sp *ServiceProvider) getAuthnrequestXML() (string, error) {
	var auth AuthnRequest
	var issuer Issuer
	var nameIDPolicy NameIDPolicy

	var requestedAuthnContext RequestedAuthnContext
	var authnContextClassRef AuthnContextClassRef

	issueInstant := time.Now().UTC().Format(time.RFC3339)
	id, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	idString := strings.Replace(id.String(), "-", "", -1)
	idString = "a" + idString[1:]

	issuer.IssuerValue = sp.Issuer

	nameIDPolicy.AllowCreate = "true"
	nameIDPolicy.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	auth.Saml = "urn:oasis:names:tc:SAML:2.0:assertion"
	auth.Samlp = "urn:oasis:names:tc:SAML:2.0:protocol"
	auth.AssertionConsumerServiceIndex = "0"
	auth.Destination = "https://mts.realme.govt.nz/logon-mts/mtsEntryPoint"
	auth.ID = idString
	auth.IssueInstant = issueInstant
	auth.ProviderName = sp.ProviderName
	auth.Version = "2.0"
	auth.Issuer = issuer
	auth.NameIDPolicy = nameIDPolicy

	authnContextClassRef.AuthnContextClassRefValue = "urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength"
	requestedAuthnContext.AuthnContextClassRef = authnContextClassRef

	auth.RequestedAuthnContext = requestedAuthnContext

	tmp, err := xml.MarshalIndent(auth, "", "  ")
	if err != nil {
		return "", err
	}
	return string(tmp), nil
}

func (sp *ServiceProvider) getSAMLRequestString() (string, error) {
	authnrequestXML, err := sp.getAuthnrequestXML()
	if err != nil {
		return "", err
	}
	deflateResult, err := defalte(authnrequestXML)
	if err != nil {
		return "", err
	}

	//err := xml.Unmarshal([]byte(data), &v)
	//os.Stdout.Write(tmp)
	//ioutil.WriteFile("./output.txt", tmp, 0666)
	//fmt.Printf("Groups: %v\n", v.Groups)

	baseEncondedContent := base64.StdEncoding.EncodeToString([]byte(deflateResult))

	QueryEscapedContent := url.QueryEscape(baseEncondedContent)
	SAMLRequestResult := "SAMLRequest=" + QueryEscapedContent
	return SAMLRequestResult, nil
}

func (sp *ServiceProvider) getSignatureString(contentForSign string) (string, error) {
	privateKey, err := ioutil.ReadFile(sp.PrivateKeyFilePath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("get pem file fail")
	}

	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	h := crypto.Hash.New(crypto.SHA1)
	_, err = h.Write([]byte(contentForSign))
	if err != nil {
		return "", err
	}
	hashed := h.Sum(nil)

	// rsa sign
	signedData, err := rsa.SignPKCS1v15(nil, private.(*rsa.PrivateKey), crypto.SHA1, hashed)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return "", err
	}

	baseEncodedData := base64.StdEncoding.EncodeToString(signedData)
	urlEncodedData := url.QueryEscape(baseEncodedData)

	return "Signature=" + urlEncodedData, nil
}

func defalte(authnrequestXML string) (string, error) {
	var deflateResult bytes.Buffer
	flateWriter, err := flate.NewWriter(&deflateResult, flate.DefaultCompression)
	if err != nil {
		return "", err
	}

	_, err = io.Copy(flateWriter, strings.NewReader(authnrequestXML))
	if err != nil {
		return "", err
	}

	err = flateWriter.Close()
	if err != nil {
		return "", err
	}
	return deflateResult.String(), nil
}

func getSigAlgString(sigAlg string) string {
	var sigAlgString string
	if sigAlg == "dsa-sha1" {
		sigAlgString = "SigAlg=" + url.QueryEscape(DSAwithSHA1)
	} else if sigAlg == "rsa-sha1" {
		sigAlgString = "SigAlg=" + url.QueryEscape(RSAwithSHA1)
	}
	return sigAlgString
}
