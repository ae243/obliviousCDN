package main

import (
	"./ocdn_crypto"
	"bufio"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const MAX_BUFFER = 4 * 1460
const (
	SERVERROR = 500
	BADREQ    = 400
)

func sendError(w net.Conn, err int) {
	// send error message correspding to error code err
	switch err {
	case SERVERROR:
		io.WriteString(w, "500 Internal Server Error\r\n")
	case BADREQ:
		io.WriteString(w, "400 Bad Request\r\n")
	default:
		io.WriteString(w, "999 Programmer Error\r\n")
	}
}

func getExitProxy() string {
	// read exit proxy table to fill in IP:Port

	// dummy values for testing on local machine - this should be read from a file or table
	return "127.0.0.1:9090"
}

func tcpProxy(w net.Conn, req *http.Request, host string, ingress bool, skey string, originkey string) {
	// start a new TCP connection with the server
	conn, err := net.Dial("tcp", host)
	if err != nil {
		sendError(w, SERVERROR)
		return
	}
	defer conn.Close()

	// Send the serialized request to the server
	err = req.Write(conn)
	if err != nil {
		sendError(w, SERVERROR)
		return
	}

	// read from the server in a loop, sending the
	// response back to the client
	connbuf := bufio.NewReader(conn)
	var buf []byte
	partial := false
	for {
		str, err := connbuf.ReadBytes('\n')
		buf = append(buf, str...)
		if err != nil {
			if err != io.EOF {
				if !partial {
					sendError(w, SERVERROR)
				}
				return
			}
			// [Annie] response formatting (strip all response headers) TODO: check what format the client proxy gets the response from exit in (are there response headers?)
			temp := strings.Split(string(buf), "Server: lighttpd/1.4.33")
			var temp2 string
			var plain_text string

			if len(temp) > 1 {
				temp2 = strings.TrimSpace(temp[1])
			} else {
				temp2 = strings.TrimSpace(temp[0])
			}

			if ingress {
				// [Annie] decrypt content with session key
				plain_text = ocdn_crypto.EncryptAES(temp2, skey)
				// [Annie] buf should now hold new plaintext content
				buf = []byte(plain_text)
			} else {
				// [Annie] decrypt content with shared key
				plain_text = ocdn_crypto.DecryptAES(temp2, originkey)

				// [Annie] encrypt content with session key
				new_cipher_text := ocdn_crypto.EncryptAES(plain_text, skey)

				// [Annie] buf should now hold new encrypted content
				buf = []byte(new_cipher_text)
			}

			w.Write(buf)
			return
		}
		if len(buf) >= MAX_BUFFER {
			_, err := w.Write(buf)
			if err != nil {
				return
			}
			buf = buf[:0]
			partial = true
		}
	}

}

func handleRequest(w net.Conn, t int64) {
	// close the connection with the socket once finished handling request
	defer w.Close()

	// read the requst from the client
	r := bufio.NewReader(w)
	req, err := http.ReadRequest(r)

	// error checking
	if err != nil {
		sendError(w, SERVERROR)
		return
	}
	if req.Method != "GET" {
		sendError(w, BADREQ)
		return
	}

	// modify the request as per the proxy specifications
	req.Header.Set("Connection", "close")
	req.Header.Set("Host", req.Host)
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	ingress := false

	// Check for presence of X-OCDN header - ingress or egress
	enc_session_key := req.Header.Get("X-OCDN")

	if enc_session_key == "" {
		// Ingress - need to set session key and redirect connection to exit proxy
		ingress = true
		pub := ocdn_crypto.ReadPublicKey()
		session_key := ocdn_crypto.GenerateSessionKey()
		enc_skey := ocdn_crypto.EncryptAsymmetric(session_key, pub)
		req.Header.Set("X-OCDN", enc_skey)

		log.Println("Ingress Header Overhead (nanoseconds): ", int64(time.Now().UnixNano())-t)
		tcpProxy(w, req, getExitProxy(), ingress, session_key, "")
	} else {
		// Egress - open connection to actual server and encrypt / decrypt content
		// get the hostname of the server
		var newHost string
		if strings.Contains(req.Host, ":") {
			newHost = req.Host
		} else {
			newHost = req.Host + ":http"
		}

		// [Annie] TODO: look up shared key in file
		key_bytes, _ := ioutil.ReadFile("shared_key.txt")
		shared_key := string(key_bytes)
		t := strings.Replace(req.URL.Path, "/", "", -1)

		// [Annie] Mangle the URL
		enc_host := ocdn_crypto.GenerateMAC(t, shared_key)
		c := "/"
		req.URL.Path = c + string(enc_host)
		log.Println("Egress mangled URL:", req.Host+req.URL.Path)

		// [Annie] Get own private key
		priv_key := ocdn_crypto.ReadPrivateKey()

		if priv_key == nil {
			log.Println("Private key not found")
			return
		}

		// [Annie] decrypt session key with private key
		session_key := ocdn_crypto.DecryptAsymmetric(enc_session_key, priv_key)
		if session_key == "" {
			log.Fatal("Session key empty!")
            return
		} else {
			tcpProxy(w, req, newHost, ingress, session_key, shared_key)
		}
	}

}

func main() {
	//Parse command line arguments
	if len(os.Args) != 2 {
		log.Fatal("Usage: server <port-number>")
	}
	portStr := ":" + os.Args[1]

	// listen on socket
	ln, err := net.Listen("tcp", portStr)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

	for {
		// accept client connections
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Accept: ", err)
			continue
		}
        // get system time for overhead calculations
		t := int64(time.Now().UnixNano())

		// start goroutine to handle client
		go handleRequest(conn, t)
	}
}
