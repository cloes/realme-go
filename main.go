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
)

func main() {

	SAMLresult := getSAMLRequestString()
	fmt.Print(SAMLresult)

}
