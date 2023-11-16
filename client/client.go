// client.go
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
	"os"
)

func generateSessionKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func readRSAPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	// Read the PEM-encoded public key from the file
	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the X.509 certificate to get the public key
	cert, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Extract the RSA public key from the certificate
	rsaPublicKey, ok := cert.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA key")
	}

	return rsaPublicKey, nil
}


func VerifySignature(data, signature []byte, publicKey *rsa.PublicKey) error {
	hashed := sha256.Sum256(data)
	return rsa.VerifyPSS(publicKey, crypto.SHA256, hashed[:], signature, nil)
}

func write(conn net.Conn, msg []byte, pubKey *rsa.PublicKey){
	
	if (pubKey != nil) {
		// Encrypt the session key with the server's public key
		encryptedMsg, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, msg, nil)
		if err != nil {
			fmt.Println("Error encrypting session key:", err)
			return
		}
		_, err = conn.Write(encryptedMsg)
		if err != nil {
			fmt.Println("Error sending encrypted session key to the server:", err)
			return
		}

	}else{
		_, err := conn.Write(msg)
		if err != nil {
			fmt.Println("Error sending encrypted session key to the server:", err)
			return
		}
	}
}

func main() {
	clientConn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer clientConn.Close()

	// Specify the desired length of the session key (in bytes)
	sessionKeyLength := 32 // Adjust the length as needed

	// Generate a session key
	sessionKey, err := generateSessionKey(sessionKeyLength)
	if err != nil {
		fmt.Println("Error generating session key:", err)
		return
	}

	fmt.Printf("Generated session key: %x\n", sessionKey)


	//open server pubkey
	// Specify the filename containing the PEM-encoded PKIX public key
	filename := "server_public.pem"

	// Read and parse the RSA public key from the file
	rsaPublicKey, err := readRSAPublicKeyFromFile(filename)
	if err != nil {
		fmt.Println("Error reading RSA public key from file:", err)
		os.Exit(1)
	}


	// Client receives data and signature from the server
	data := sessionKey
	write(clientConn, data, rsaPublicKey)

	// // Verify the signature using the server's public key
	// err = VerifySignature(data, signatureBytes, serverPublicKey)
	// if err != nil {
	// 	fmt.Println("Error verifying signature:", err)
	// 	return
	// }

	// fmt.Println("Successfully received data and verified RSA-PSS signature.")
}
