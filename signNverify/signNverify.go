// https://www.sohamkamani.com/golang/rsa-encryption/
// https://gist.github.com/sohamkamani/08377222d5e3e6bc130827f83b0c073e

package signNverify

import (
	// "crypto"
	"crypto/rand"
	"crypto/rsa"
	// "crypto/sha512"
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

// 		encryptedBytes, err := rsa.EncryptOAEP(
// 			sha512.New(),
// 			rand.Reader,
// 			&publicKey,
// 			[]byte("super secret message"),
// 			nil)
// 		if err != nil {
// 			log.Fatalln(err)
// 		}

// 		fmt.Println("encrypted bytes: ", encryptedBytes)

// 		// The first argument is an optional random data generator (the rand.Reader we used before)
// 		// we can set this value as nil
// 		// The OEAPOptions in the end signify that we encrypted the data using OEAP, and that we used
// 		// SHA256 to hash the input.
// 		decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA512})
// 		if err != nil {
// 			log.Fatalln(err)
// 		}

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

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	bitSize := 1024 // You can modify this to change the key size

	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func WritePrivateKeyToFile(privateKey *rsa.PrivateKey, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	err = pem.Encode(file, privateKeyPEM)
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

	// // Type assertion to access the RSA private key
    // rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
    // if !ok {
    //     fmt.Println("Not an RSA private key")
    //     return nil, errors.New("fail to convert x509PrivateKey type to rsaPrivateKey")
    // }

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
		keyBytes, _ = x509.MarshalPKIXPublicKey(k)
	default:
		return ""
	}

	block := &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	}

	return string(pem.EncodeToMemory(block))
}