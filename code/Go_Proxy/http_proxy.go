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

    skey := encrypt(generateKey(), pk) [Client proxy] generate session key
    req.Header.Add("skey", skey)  //[Client proxy] Annie added this for adding a session key to the message (encrypted with exit proxy's public key)

	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	// get the hostname of the server
	var newHost string
	if strings.Contains(req.Host, ":") {
		newHost = req.Host
	} else {
		newHost = req.Host + ":http"
	}

	// start a new TCP connection with the server
	conn, err := net.Dial("tcp", newHost)
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
			w.Write(buf)
			return
		}
		if len(buf) >= MAX_BUFFER {
            // [Client proxy] Annie added this -- decrypt str here (with session key) --- or do we decrypt somewhere else? 
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
