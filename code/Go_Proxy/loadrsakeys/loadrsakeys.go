package loadrsakeys

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"
    //"fmt"
    //"io/ioutil"
)

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
    privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
    return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
    privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
    privkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PRIVATE KEY",
                    Bytes: privkey_bytes,
            },
    )
    return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
            return nil, err
    }

    return priv, nil
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
    pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
    if err != nil {
            return "", err
    }
    pubkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PUBLIC KEY",
                    Bytes: pubkey_bytes,
            },
    )

    return string(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
            return nil, err
    }

    switch pub := pub.(type) {
    case *rsa.PublicKey:
            return pub, nil
    default:
            break // fall through
    }
    return nil, errors.New("Key type is not RSA")
}

/*
func main() {

    // Create the keys
    priv, pub := GenerateRsaKeyPair()

    // Export the keys to pem string
    priv_pem := ExportRsaPrivateKeyAsPemStr(priv)
    pub_pem, _ := ExportRsaPublicKeyAsPemStr(pub)

    ioutil.WriteFile("priv_test.pem", []byte(priv_pem), 0644)
    ioutil.WriteFile("pub_test.pem", []byte(pub_pem), 0644)

    // Read pem strings from file
    pub_bytes, _ := ioutil.ReadFile("public.pem")
    pub_pem := string(pub_bytes)

    priv_bytes, _ := ioutil.ReadFile("private.pem")
    priv_pem := string(priv_bytes)


    priv_bytes, _ := ioutil.ReadFile("priv_test.pem")
    pub_bytes, _ := ioutil.ReadFile("pub_test.pem")

    new_priv_pem := string(priv_bytes)
    new_pub_pem := string(pub_bytes)

    // Import the keys from pem string
    privx, _ := ParseRsaPrivateKeyFromPemStr(new_priv_pem)
    pubx, _ := ParseRsaPublicKeyFromPemStr(new_pub_pem)

    if privx == nil {
        fmt.Println("PRIV IS NIL")
    }
    if pubx == nil {
        fmt.Println("PUB IS NIL")
    }

    // Export the newly imported keys
    priv_parsed_pem := ExportRsaPrivateKeyAsPemStr(priv_parsed)
    pub_parsed_pem, _ := ExportRsaPublicKeyAsPemStr(pub_parsed)

    fmt.Println(priv_parsed_pem)
    fmt.Println(pub_parsed_pem)

    
    // Check that the exported/imported keys match the original keys
    if priv_pem != priv_parsed_pem || pub_pem != pub_parsed_pem {
            fmt.Println("Failure: Export and Import did not result in same Keys")
    } else {
            fmt.Println("Success")
    }
}*/
