package main

import (
	"fmt"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"strings"
)

//接收返回的xml
func getSamlpResponseResult(XMLString string){

	baseDecodedContent,_ := base64.StdEncoding.DecodeString(XMLString)
	fmt.Println(baseDecodedContent)

}


type ResponseContent struct {
	responseStatusCode string
	responsePrivateKey string
	responseEncryptedContent string
}

//解析xml,返回statuscode、responsePrivateKey、responseEncryptedContent
func getResponseContent() ResponseContent{

	type StatusCode struct {
		XMLName xml.Name `xml:"StatusCode"`
		Value string `xml:"Value,attr"`
	}

	type Status struct {
		XMLName xml.Name `xml:"Status"`
		StatusCode StatusCode
	}

	type CipherValue struct{
		XMLName xml.Name `xml:"CipherValue"`
		Value string `xml:",chardata"`
	}

	type CipherData struct {
		XMLName xml.Name `xml:"CipherData"`
		CipherValue CipherValue
	}

	type EncryptedKey struct {
		XMLName xml.Name `xml:"EncryptedKey"`
		CipherData CipherData
	}

	type KeyInfo struct {
		XMLName xml.Name `xml:"KeyInfo"`
		EncryptedKey EncryptedKey
	}

	type EncryptedData struct {
		XMLName xml.Name `xml:"EncryptedData"`
		KeyInfo KeyInfo
		CipherData CipherData
	}

	type EncryptedAssertion struct {
		XMLName xml.Name `xml:"EncryptedAssertion"`
		EncryptedData EncryptedData
	}

	type Response struct {
		XMLName xml.Name `xml:"Response"`
		Status Status
		EncryptedAssertion EncryptedAssertion
	}

	v := Response{}
	data, err:= ioutil.ReadFile("samlResponse.txt")
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	err = xml.Unmarshal(data, &v)
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}

	resposeStatusCode := v.Status.StatusCode.Value
	fmt.Println(resposeStatusCode)

	resposePrivateKey := v.EncryptedAssertion.EncryptedData.KeyInfo.EncryptedKey.CipherData.CipherValue.Value
	resposePrivateKey = strings.Replace(resposePrivateKey," ", "",-1)
	BaseDecodedResposePrivateKey,_ := base64.StdEncoding.DecodeString(resposePrivateKey)
	fmt.Println(BaseDecodedResposePrivateKey)

	resposeEncryptedContent := v.EncryptedAssertion.EncryptedData.CipherData.CipherValue.Value
	BaseDecodedresposeEncryptedContent,_ := base64.StdEncoding.DecodeString(resposeEncryptedContent)
	//fmt.Println(BaseDecodedresposeEncryptedContent)

	responseContent := ResponseContent{
		responseStatusCode:resposeStatusCode,
		responsePrivateKey:string(BaseDecodedResposePrivateKey),
		responseEncryptedContent:string(BaseDecodedresposeEncryptedContent),
	}

	return responseContent
}


func getAESKEY()([]byte, error){
	privateKey,err := ioutil.ReadFile("private_key.txt")
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		//return nil, err.New("private key error!")
		fmt.Println("Something went wrong")
	}

	//fmt.Println(block.Type)
	//fmt.Println(block.Headers)

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}

	data,err := ioutil.ReadFile("aes_key.txt")
	data2,_ := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv.(*rsa.PrivateKey), data2)

}

func main(){
	//responseContent := getResponseContent()
	tmp,err := getAESKEY()
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	fmt.Println(string(tmp))

}