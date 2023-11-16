package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func generateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

func savePEMKey(filename string, key *rsa.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(key)

	err = pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return err
	}

	fmt.Printf("Private key saved to %s\n", filename)
	return nil
}

func savePEMPublicKey(filename string, pubkey *rsa.PublicKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}

	err = pem.Encode(file, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	if err != nil {
		return err
	}

	fmt.Printf("Public key saved to %s\n", filename)
	return nil
}

func main() {
	privateKey, publicKey, err := generateRSAKeyPair(2048)
	if err != nil {
		fmt.Println("Error generating RSA key pair:", err)
		return
	}

	err = savePEMKey("private.pem", privateKey)
	if err != nil {
		fmt.Println("Error saving private key:", err)
		return
	}

	err = savePEMPublicKey("public.pem", publicKey)
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return
	}
}
