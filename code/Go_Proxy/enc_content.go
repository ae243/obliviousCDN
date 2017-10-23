package main

import (
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "strings"
)

func main() {

    files, err := ioutil.ReadDir("test_dir")
    if err != nil {
        fmt.Println(err)
    }

    // read in shared key
    key_bytes, _ := ioutil.ReadFile("shared_key.txt")
    key := string(key_bytes)

    for _, f := range files {
        fmt.Println(f.Name())
        // read in plaintext file
        content_bytes, _ := ioutil.ReadFile("test_dir/" + f.Name())

        plaintext := string(content_bytes)

        fmt.Println(plaintext)

        // encrypt plaintext with shared key
        ciphertext := base64.StdEncoding.EncodeToString([]byte(encryptAES(plaintext, key)))

        // compute HMAC(filename)
        enc_filename := generateMAC(f.Name(), key)
        clean_enc_filename := strings.Replace(enc_filename, "/", "-", -1)

        // write ciphertext to file named with HMAC(f.Name())
        ioutil.WriteFile("test_dir/" + clean_enc_filename, []byte(ciphertext), 0644)
    
        // compute encrypted filename for lookup
        enc_filename2 := generateMAC(f.Name(), key)
        clean_enc_filename2 := strings.Replace(enc_filename2, "/", "-", -1)

        // read enc_filename2
        enc_bytes, err := ioutil.ReadFile("test_dir/" + clean_enc_filename2)
        if err != nil {
            fmt.Println(err)
        }
        enc_content := string(enc_bytes)

        enc1, err := base64.StdEncoding.DecodeString(enc_content)
        if err != nil {
            fmt.Println(err)
        }
        enc2 := string(enc1)

        // decrypt content
        dec := decryptAES(enc2, key)   

        if dec == plaintext {
            fmt.Println("SUCCESS")
        } else {
            fmt.Println("FAILURE")
        }
    }
}
