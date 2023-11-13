package main

import (
	"KI5/tugas1/signNverify"
	// "crypto/des"
	"crypto/rsa"
	"fmt"
	"net"
)

func send(conn net.Conn, buffer []byte) (int){
	_, err := conn.Write(buffer)
	if err != nil {
		fmt.Println("Error sending:", err)
		return 0
	}

	fmt.Printf("\n\nServer: %s\n", buffer)
	return len(buffer)
}

func read(conn net.Conn) ([]byte, int){
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err)
		return nil, 0
	}
	
	fmt.Printf("\n\nClient: %s\n", buffer)
	return buffer, n
}

func GeneratePrivateKey(filename string){
	bitSize := 9182

	privKey := signNverify.GenerateKeys(bitSize) 
	
	err := signNverify.SaveRsaPrivateKey(privKey, filename) 
	if err != nil {
		fmt.Println("Error saving private key:", err)
	}
}

func handleClient(conn net.Conn, privateKey *rsa.PrivateKey) {
	defer conn.Close()
	
	//1. SEND Server PUB KEY
	message := signNverify.RsaToByte(&privateKey.PublicKey)
	send(conn, message)

	//1. GET CONFIRM
	read(conn)
	
	//1. (BONUS) GET Encrypted Client PUB KEY
	encryptedBytes, n := read(conn)
	decryptedBytes := signNverify.DecryptMessage(privateKey, encryptedBytes[:n])
	_, clientKey := signNverify.RsaFromString(string(decryptedBytes))
	fmt.Printf("\n\nClient Key Decrypted message: %s\n", signNverify.RsaToByte(clientKey))

	//1. SEND CONFIRM
	message = []byte("confirm")
	send(conn, message)

	//1. SEND Pub Session Key
	sessionKey := signNverify.GenerateKeys(2048)
	message = signNverify.RsaToByte(&sessionKey.PublicKey)
	encryptedBytes = signNverify.EncryptMessage(clientKey, message)
	send(conn, encryptedBytes)

	//1. GET CONFIRM
	read(conn)

	//1. GET MESSAGE
	encryptedBytes, n = read(conn)
	decryptedBytes = signNverify.DecryptMessage(sessionKey, encryptedBytes[:n])
	fmt.Println("DECRYPTED MESSAGE: ", string(decryptedBytes))

	//1. SEND CONFIRM
	message = []byte("confirm")
	send(conn, message)
}

func main() {
	filename := "server_private.key"
	// GeneratePrivateKey(filename)

	privateKey := signNverify.GetKeys(filename) 

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Server is listening on port 8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			return
		}

		go handleClient(conn, privateKey)
	}
}
