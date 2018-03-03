# Realme-GO-SDK

example

    package main

    import (
        "./Realme-GO-SDK"
        "io/ioutil"
        "fmt"
    )

    func main() {
        xmldata,_ := ioutil.ReadFile("./Realme-GO-SDK/samlResponse.txt")
        RSAPrivateKey,_ := ioutil.ReadFile("./Realme-GO-SDK/private_key.txt")
        output := RealmeGOSDK.GetResponseDecryptedContent(xmldata,RSAPrivateKey)
        fmt.Println(output.StatusCode)
        fmt.Println(output.NameID)
    }
