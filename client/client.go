package main

import (
	"crypto/rsa"
	"fmt"
	"net"

	// "bufio"
	// "os"
	"KI5/tugas1/signNverify"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	privateKey, err := GenerateKeys()
	if err != nil{
		fmt.Println("Error generating private key:", err)
	}

	err = SaveKeys(privateKey, "client_private.key") 
	if err != nil {
		fmt.Println("Error writing private key to file:", err)
	}

	_, err = GetKeys("client_private.key") 
	if err != nil {
		fmt.Println("Error reading private key to file:", err)
	}
	// //take command
	// reader := bufio.NewReader(os.Stdin)

	// fmt.Print("Enter a message: ")
	// command, err := reader.ReadString('\n')
	// if err != nil {
	// 	fmt.Println("Error reading input:", err)
	// 	return
	// }

	// Send a message to the server
	// message := command
	// _, err = conn.Write([]byte(message))
	// if err != nil {
	// 	fmt.Println("Error sending:", err)
	// 	return
	// }

	// // Read the response from the server
	// buffer := make([]byte, 1024)
	// n, err := conn.Read(buffer)
	// if err != nil {
	// 	fmt.Println("Error reading:", err)
	// 	return
	// }

	// fmt.Printf("Response from server: %s\n", buffer[:n])
}

func GenerateKeys() (*rsa.PrivateKey, error){
	privateKey, err := signNverify.GenerateRSAKey()
	if err != nil { return nil, err }

	privateKeyString := signNverify.RsaToString(privateKey)
	fmt.Println("Private Key String:")
	fmt.Println(privateKeyString)

	publicKeyString := signNverify.RsaToString(&privateKey.PublicKey)
	fmt.Println("Public Key String:")
	fmt.Println(publicKeyString)

	return privateKey, nil
}

func SaveKeys(privateKey *rsa.PrivateKey, filename string) error{
	err := signNverify.WritePrivateKeyToFile(privateKey, filename)
	if err != nil { return err }

	fmt.Printf("Success saving key file to: %s\n", filename)
	return nil
}

func GetKeys(filename string) (*rsa.PrivateKey, error){
	privateKey, err := signNverify.ReadPrivateKeyFromFile(filename)
	if err != nil { return nil, err }

	privateKeyString := signNverify.RsaToString(privateKey)
	fmt.Println("Private Key String:")
	fmt.Println(privateKeyString)

	publicKeyString := signNverify.RsaToString(&privateKey.PublicKey)
	fmt.Println("Public Key String:")
	fmt.Println(publicKeyString)

	return privateKey, err
}
