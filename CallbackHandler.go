package main

import (
	"fmt"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	//"crypto/rand"
	"strings"
	"crypto/aes"
	"crypto/cipher"
)

//接收返回的xml
func getSamlpResponseResult(XMLString string){

	baseDecodedContent,_ := base64.StdEncoding.DecodeString(XMLString)
	fmt.Println(baseDecodedContent)

}


type ResponseContent struct {
	responseStatusCode string
	responsePrivateKey string
	AESEncryptedContent string
	AESKey string
	iv string
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
	//fmt.Println(BaseDecodedResposePrivateKey)

	resposeEncryptedContent := v.EncryptedAssertion.EncryptedData.CipherData.CipherValue.Value
	resposeEncryptedContent = strings.Replace(resposeEncryptedContent," ", "",-1)
	BaseDecodedresposeEncryptedContent,_ := base64.StdEncoding.DecodeString(resposeEncryptedContent)
	iv := BaseDecodedresposeEncryptedContent[:16]
	AESEncryptedContent := BaseDecodedresposeEncryptedContent[16:]
	//fmt.Println(BaseDecodedresposeEncryptedContent)

	responseContent := ResponseContent{
		responseStatusCode:resposeStatusCode,
		responsePrivateKey:string(BaseDecodedResposePrivateKey),
		AESEncryptedContent:string(AESEncryptedContent),
		iv:string(iv),
	}

	return responseContent
}


func getAESKEY(RSAEncryptContent string)([]byte, error){
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

	/*
	data,err := ioutil.ReadFile("aes_key.txt")
	data2,_ := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	*/
	//return rsa.DecryptPKCS1v15(rand.Reader, priv.(*rsa.PrivateKey), []byte(RSAEncryptContent))
	return rsa.DecryptPKCS1v15(nil, priv.(*rsa.PrivateKey), []byte(RSAEncryptContent))

}

func getAESDecryptContent(responseContent ResponseContent)[]byte{
	block, err := aes.NewCipher([]byte(responseContent.AESKey))
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	//blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, []byte(responseContent.iv))
	origData := make([]byte, len(responseContent.AESEncryptedContent))
	// origData := crypted
	blockMode.CryptBlocks(origData, []byte(responseContent.AESEncryptedContent))
	origData = PKCS5UnPadding(origData)
	//origData = ZeroUnPadding(origData)
	fmt.Println(string(origData))
	//ioutil.WriteFile("AESDEcrypt",origData,666)
	return origData

}


func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func main(){
	responseContent := getResponseContent()
	AESKey,err := getAESKEY(responseContent.responsePrivateKey)
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	responseContent.AESKey = string(AESKey)

	getAESDecryptContent(responseContent)

}