package main

import (
	//"bytes"
	//"compress/flate"
	//"encoding/xml"
	"fmt"
	//"io/ioutil"
	//"os"
	//"strings"
	//"time"
	//"github.com/satori/go.uuid"
	//"io"
	//"encoding/base64"
	//"net/url"
	"io/ioutil"
)

func main() {

	//SAMLresult := getSAMLRequestString()
	//fmt.Print(SAMLresult)
	output := getQueryString("rsa-sha1","")
	fmt.Println(output)
	ioutil.WriteFile("output_url",[]byte(output),666)

}
