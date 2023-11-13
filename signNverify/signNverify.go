// https://www.sohamkamani.com/golang/rsa-encryption/
// https://gist.github.com/sohamkamani/08377222d5e3e6bc130827f83b0c073e

package signNverify

import (
	// "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	// "log"
	"os"
	// "io/ioutil"
	// "errors"
)

// func main(){
// 	// The GenerateKey method takes in a reader that returns random bits, and
// 	// the number of bits
// 	//privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
// 	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}

// 	// The public key is a part of the *rsa.PrivateKey struct
// 	publicKey := privateKey.PublicKey

// 	// fokus di sign saja
// 	if false {



// 		fmt.Println("encrypted bytes: ", encryptedBytes)

// 		// The first argument is an optional random data generator (the rand.Reader we used before)
// 		// we can set this value as nil
// 		// The OEAPOptions in the end signify that we encrypted the data using OEAP, and that we used
// 		// SHA256 to hash the input.


// 		// We get back the original information in the form of bytes, which we
// 		// the cast to a string and print
// 		fmt.Println("decrypted message: ", string(decryptedBytes))

// 	}

// 	msg := []byte("verifiable message")

// 	// Before signing, we need to hash our message
// 	// The hash is what we actually sign
// 	msgHash := sha512.New()
// 	_, err = msgHash.Write(msg)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	msgHashSum := msgHash.Sum(nil)

// 	// In order to generate the signature, we provide a random number generator,
// 	// our private key, the hashing algorithm that we used, and the hash sum
// 	// of our message
// 	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, msgHashSum, nil)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}

// 	// To verify the signature, we provide the public key, the hashing algorithm
// 	// the hash sum of our message and the signature we generated previously
// 	// there is an optional "options" parameter which can omit for now
// 	err = rsa.VerifyPSS(&publicKey, crypto.SHA512, msgHashSum, signature, nil)
// 	if err != nil {
// 		fmt.Println("could not verify signature: ", err)
// 		return
// 	}
// 	// If we don't get any error from the `VerifyPSS` method, that means our
// 	// signature is valid
// 	fmt.Println("signature verified")
// }

func GenerateRSAKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func WriteRsaPrivateKeyToFile(privateKey *rsa.PrivateKey, filename string) error {
	
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	
	privateKeyfile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer privateKeyfile.Close()
	
	err = pem.Encode(privateKeyfile, privateKeyBlock)
	if err != nil {
		return err
	}

	return nil
}

func writeRsaPublicKeyToFile(publicKey *rsa.PublicKey, filename string) error {
	pubKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}

	pubKeyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer pubKeyFile.Close()

	err = pem.Encode(pubKeyFile, pubKeyBlock)
	if err != nil {
		return err
	}

	return nil
}

func ReadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func RsaToString(key interface{}) string {
	var keyType string
	var keyBytes []byte

	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyType = "RSA PRIVATE KEY"
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
	case *rsa.PublicKey:
		keyType = "PUBLIC KEY"
		keyBytes = x509.MarshalPKCS1PublicKey(k)
	default:
		return ""
	}

	block := &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	}

	return string(pem.EncodeToMemory(block))
}

func RsaToByte(key interface{}) []byte {
	return []byte(RsaToString(key))
}

func RsaFromString(keyString string) (*rsa.PrivateKey, *rsa.PublicKey) {
	block, _ := pem.Decode([]byte(keyString))
	if block == nil {
		fmt.Println("failed to decode PEM block")
		return nil, nil 
	}

	if block.Type == "RSA PRIVATE KEY" {
		privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil
		}
		return privKey, &privKey.PublicKey
	} else if block.Type == "PUBLIC KEY" {
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			fmt.Println("failed to decode PEM block")
			return nil, nil
		}
		return nil, pubKey
	}

	fmt.Println("unknown key type")
	return nil, nil
}

func GenerateKeys(bitSize int) (*rsa.PrivateKey){
	privateKey, err := GenerateRSAKey(bitSize)
	if err != nil { 
		fmt.Println("Error generating keys: ", err)
		return nil 
	}

	privateKeyString := RsaToString(privateKey)
	fmt.Println("Private Key String:")
	fmt.Println(privateKeyString)

	publicKeyString := RsaToString(&privateKey.PublicKey)
	fmt.Println("Public Key String:")
	fmt.Println(publicKeyString)

	return privateKey
}

func SaveRsaPrivateKey(privateKey *rsa.PrivateKey, filename string) error{
	err := WriteRsaPrivateKeyToFile(privateKey, filename)
	if err != nil { return err }

	fmt.Printf("Success saving private key file to: %s\n", filename)
	return nil
}

func SaveRsaPublicKey(publicKey *rsa.PublicKey, filename string) error{
	err := writeRsaPublicKeyToFile(publicKey, filename)
	if err != nil { return err }

	fmt.Printf("Success saving public key file to: %s\n", filename)
	return nil
}

func GetKeys(filename string) (*rsa.PrivateKey){
	privateKey, err := ReadPrivateKeyFromFile(filename)
	if err != nil { 
		fmt.Println("Error reading file: ", err)
		return nil 
	}

	privateKeyString := RsaToString(privateKey)
	fmt.Println("Private Key String:")
	fmt.Println(privateKeyString)

	publicKeyString := RsaToString(&privateKey.PublicKey)
	fmt.Println("Public Key String:")
	fmt.Println(publicKeyString)

	return privateKey
}

func EncryptMessage(publicKey *rsa.PublicKey, message []byte) ([]byte){
	fmt.Println("Key Len:", publicKey.Size()) 
	fmt.Printf("Message Len: %s, LENGTH %d\n", message, len(message) + 64 + 2) 
	
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		message,
		nil)
	if err != nil {
		fmt.Println("Error encrypting:", err) 
	}

	return encryptedBytes
}

func DecryptMessage(privateKey *rsa.PrivateKey, encryptedBytes []byte) ([]byte){
	fmt.Println("Key Len:", privateKey.Size()) 
	fmt.Println("ENCRYPTED Len:", len(encryptedBytes)) 
	
	decryptedBytes, err := rsa.DecryptOAEP(
		sha256.New(), 
		nil, 
		privateKey, 
		encryptedBytes, 
		nil)
	if err != nil {
		fmt.Println("Error decrypting:", err) 
	}

	return decryptedBytes
}