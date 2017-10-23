package main

import (
    "encoding/base64"
    "fmt"
    "io/ioutil"
    //"strings"
)

func main() {

    // create encrypted file/identifier
    filename := "9991.txt"

    // read in plaintext file
    content_bytes, _ := ioutil.ReadFile(filename)

    plaintext := string(content_bytes)

    // read in shared key
    key_bytes, _ := ioutil.ReadFile("shared_key.txt")
    key := string(key_bytes)

    // encrypt plaintext with shared key
    ciphertext := base64.StdEncoding.EncodeToString([]byte(encryptAES(plaintext, key)))

    // compute HMAC(filename)
    enc_filename := generateMAC(filename, key)

    // write ciphertext to file named with HMAC(filename)
    ioutil.WriteFile(enc_filename, []byte(ciphertext), 0644)

    // decrypt file/identifier
    
    // compute encrypted filename for lookup
    enc_filename2 := generateMAC(filename, key)

    // read enc_filename2
    enc_bytes, _ := ioutil.ReadFile(enc_filename2)
    enc_content := string(enc_bytes)

    enc1, err := base64.StdEncoding.DecodeString(enc_content)
    if err != nil {
        fmt.Println(err)
    }
    enc2 := string(enc1)

    // decrypt content
    dec := decryptAES(enc2, key)

    //dec_content_bytes, err := base64.StdEncoding.DecodeString(dec)

    //dec_content := string(dec_content_bytes)    

    if dec == plaintext {
        fmt.Println("SUCCESS")
    } else {
        fmt.Println("FAILURE")
    }
}
