package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

const MAX_BUFFER   = 4*1460
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


func handleRequest(w net.Conn) {
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

    // [Annie] TODO: Client must look up exit proxy in file (this file has URL -> exit_IP)
    
    // [Annie] read in public key -- assume we know all public keys
    pub := readPublicKey()                                

    // [Annie] create a session key
    skey := generateSessionKey()

    // [Annie] encrypt the session key with the proxy's public key and add as header
    enc_skey := encryptAsymmetric(skey, pub)
    req.Header.Add("X-OCDN", enc_skey) 

	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
/*
	// get the hostname of the server
	var newHost string
	if strings.Contains(req.Host, ":") {
		newHost = req.Host
	} else {
		newHost = req.Host + ":http"
	}
*/
	// start a new TCP connection with the server
	conn, err := net.Dial("tcp", "127.0.0.1:9090") //  [Annie] hardcoded for now (exit proxy)
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
            temp := strings.Split(string(buf),"Server: lighttpd/1.4.33")
            var temp2 string            
            if len(temp) > 1 {
                temp2 = strings.TrimSpace(temp[1])
            } else {
                temp2 = strings.TrimSpace(temp[0])
            }

            // [Annie] decrypt content with session key
            plain_text := decryptAES(temp2, skey)

            // [Annie] buf should now hold new plaintext content
            buf = []byte(plain_text)
			w.Write(buf)
			return
		}
		if len(buf) >= MAX_BUFFER {
            // TODO (possibly): [Client proxy] Annie added this -- decrypt str here (with session key)
			_, err := w.Write(buf)
			if err != nil {
				return
			}
			buf = buf[:0]
			partial = true
		}
	}
}

func main() {
	//Parse command line arguments
	if len(os.Args) != 2 {
		log.Fatal("Usage: server <port-number>")
	}
	portStr :=  ":" + os.Args[1]

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
		// start goroutine to handle client
		go handleRequest(conn)
	}
}
