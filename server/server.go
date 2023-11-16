// server.go
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"io/ioutil"
)

func SignData(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func readRSAPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	// Read the PEM-encoded private key from the file
	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func main() {
	go func() {
		listener, err := net.Listen("tcp", ":8080")
		if err != nil {
			fmt.Println("Error starting server:", err)
			return
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				return
			}
			defer conn.Close()

			// Send public key to the client
			encryptedSessionKey := make([]byte, 256) // Adjust the buffer size accordingly
			_, err = conn.Read(encryptedSessionKey)
			if err != nil {
				fmt.Println("Error receiving encrypted session key from the client:", err)
				return
			}

			filename := "server_private.pem"
			privateKey, err := readRSAPrivateKeyFromFile(filename)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				return
			}

			sessionKey, err := privateKey.Decrypt(nil, encryptedSessionKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
			if err != nil {
				fmt.Println("Error decrypting session key:", err)
				return
			}

			fmt.Println(sessionKey)
		}
	}()

	fmt.Println("Server started. Waiting for connections...")
	select {}
}
