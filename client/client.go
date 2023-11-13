package main

import (
	"fmt"
	"net"

	// "bufio"
	// "os"
	"KI5/tugas1/signNverify"
)

func GeneratePrivateKey(filename string){
	bitSize := 4096

	privKey := signNverify.GenerateKeys(bitSize) 
	
	err := signNverify.SaveRsaPrivateKey(privKey, filename) 
	if err != nil {
		fmt.Println("Error saving private key:", err)
	}
}

func send(conn net.Conn, buffer []byte) (int){
	_, err := conn.Write(buffer)
	if err != nil {
		fmt.Println("Error sending:", err)
		return 0
	}

	fmt.Printf("\n\nClient: %s\n", buffer)
	return len(buffer)
}

func read(conn net.Conn) ([]byte, int){
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err)
		return nil, 0
	}

	fmt.Printf("\n\nServer: %s\n", buffer)
	return buffer, n
}

func main() {
	filename := "client_private.key"
	GeneratePrivateKey(filename)
	privateKey := signNverify.GetKeys(filename)

	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	

	//1. Get Server PUB KEY
	buffer, n := read(conn)

	_, serverKey := signNverify.RsaFromString(string(buffer[:n]))
	if err != nil {
		fmt.Println("Error converting string to rsa:", err)
		return
	}

	//1. SEND CONFIRM
	message := []byte("confirm")
	send(conn, message)
	
	//1. (BONUS) SEND Client PUB KEY
	message = signNverify.RsaToByte(&privateKey.PublicKey)
	encryptedBytes := signNverify.EncryptMessage(serverKey, message)
	send(conn, encryptedBytes)
	
	//1. GET CONFIRM
	read(conn)
	
	//1. GET Pub Session Key
	encryptedBytes, n = read(conn)
	decryptedBytes := signNverify.DecryptMessage(privateKey, encryptedBytes[:n])
	_, sessionKey := signNverify.RsaFromString(string(decryptedBytes))
	fmt.Printf("\n\nClient Key Decrypted message: %s\n", signNverify.RsaToByte(sessionKey))

	// //1. SEND CONFIRM
	message = []byte("confirm")
	send(conn, message)

	//1. SEND MESSAGE
	message = signNverify.EncryptMessage(sessionKey, []byte("This is my secret"))
	send(conn, message)

	//1. GET CONFIRM
	read(conn)
}