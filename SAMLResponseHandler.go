package RealmeGOSDK

import (
	"fmt"
	"encoding/base64"
	"encoding/xml"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"strings"
	"crypto/aes"
	"crypto/cipher"
)

type ResponseContent struct {
	responseStatusCode string
	responsePrivateKey string
	AESEncryptedContent string
	AESKey string
	iv string
}

type DecryptedResponse struct {
	StatusCode string
	NameID string
}


/*
 * 解析xml,返回ResponseContent结构体
 *
 */
func getResponseContent(data []byte) ResponseContent{
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
	err := xml.Unmarshal(data, &v)
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}

	resposeStatusCode := v.Status.StatusCode.Value
	lastIndex := strings.LastIndex(resposeStatusCode,":")
	resposeStatusCode = resposeStatusCode[lastIndex+1:]
	//fmt.Println(resposeStatusCode)

	resposePrivateKey := v.EncryptedAssertion.EncryptedData.KeyInfo.EncryptedKey.CipherData.CipherValue.Value
	resposePrivateKey = strings.Replace(resposePrivateKey," ", "",-1)
	BaseDecodedResposePrivateKey,_ := base64.StdEncoding.DecodeString(resposePrivateKey)

	resposeEncryptedContent := v.EncryptedAssertion.EncryptedData.CipherData.CipherValue.Value
	resposeEncryptedContent = strings.Replace(resposeEncryptedContent," ", "",-1)
	BaseDecodedresposeEncryptedContent,_ := base64.StdEncoding.DecodeString(resposeEncryptedContent)

	iv := BaseDecodedresposeEncryptedContent[:16]
	AESEncryptedContent := BaseDecodedresposeEncryptedContent[16:]

	responseContent := ResponseContent{
		responseStatusCode:resposeStatusCode,
		responsePrivateKey:string(BaseDecodedResposePrivateKey),
		AESEncryptedContent:string(AESEncryptedContent),
		iv:string(iv),
	}

	return responseContent
}

/**
 * 对SAML Response中的key进行RSA解密,获取AES的秘钥
 */
func getAESKEY(RSAEncryptContent string,privateKey []byte)([]byte, error){
	/*
	privateKey,err := ioutil.ReadFile("private_key.txt")
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	*/
	block, _ := pem.Decode(privateKey)
	if block == nil {
		fmt.Println("Something went wrong")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}

	return rsa.DecryptPKCS1v15(nil, priv.(*rsa.PrivateKey), []byte(RSAEncryptContent))
}


/*
 * 使用AES秘钥对SAML Response的内容进行解密
 */
func getAESDecryptContent(responseContent ResponseContent)[]byte{
	block, err := aes.NewCipher([]byte(responseContent.AESKey))
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	//blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, []byte(responseContent.iv))
	origData := make([]byte, len(responseContent.AESEncryptedContent))
	blockMode.CryptBlocks(origData, []byte(responseContent.AESEncryptedContent))
	origData = PKCS5UnPadding(origData)

	return origData
}

/**
 * 删除AES加密前的Padding
 */
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}


/**
 * 获取AES加密内容中的NameID属性
 */
func getNameID(AESDecryptContent []byte) string{
	type NameID struct {
		XMLName xml.Name `xml:"NameID"`
		Value string `xml:",chardata"`
	}

	type Subject struct {
		XMLName xml.Name `xml:"Subject"`
		NameID NameID
	}

	type Assertion struct {
		XMLName xml.Name `xml:"Assertion"`
		Subject Subject
	}

	v := Assertion{}
	err := xml.Unmarshal(AESDecryptContent, &v)
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	return v.Subject.NameID.Value
}


/**
 * SDK的主入口，输入xml的内容，返回解密后的DecryptedResponse
 */
func GetResponseDecryptedContent(data, RSAPrivateKey []byte) DecryptedResponse{
	//data, _:= ioutil.ReadFile("samlResponse.txt")

	responseContent := getResponseContent(data)
	AESKey,err := getAESKEY(responseContent.responsePrivateKey,RSAPrivateKey)
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
	}
	responseContent.AESKey = string(AESKey)

	AESDecryptContent := getAESDecryptContent(responseContent)
	nameID := getNameID(AESDecryptContent)

	decryptedResponse := DecryptedResponse{
		StatusCode:responseContent.responseStatusCode,
		NameID:nameID,
	}

	return decryptedResponse
}