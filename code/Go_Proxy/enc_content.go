package main

import (
    "fmt"
    "io/ioutil"
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
    ciphertext := encryptAES(plaintext, key)

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
    
    // decrypt content
    dec_content := decryptAES(enc_content, key)
    
    if dec_content == plaintext {
        fmt.Println("SUCCESS")
    } else {
        fmt.Println("FAILURE")
    }
}
