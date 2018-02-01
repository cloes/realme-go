package main

import (
	"fmt"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
)

//接收返回的xml
func getSamlpResponseResult(XMLString string){

	baseDecodedContent,_ := base64.StdEncoding.DecodeString(XMLString)
	fmt.Println(baseDecodedContent)


}


func getEncryptedContent(){

	type StatusCode struct {
		XMLName xml.Name `xml:"StatusCode"`
		Value string `xml:"Value,attr"`
	}

	type Status struct {
		XMLName xml.Name `xml:"Status"`
		StatusCode StatusCode
	}

	type Response struct {
		XMLName xml.Name `xml:"Response"`
		Status Status
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
	fmt.Println(v.Status.StatusCode.Value)


}

func main(){
	getEncryptedContent()

}