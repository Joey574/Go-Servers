package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	print("Worker Started\n")

	ipAddress := "127.0.0.1"
	port := "1234"
	address := ipAddress + ":" + port

	conn, err := net.Dial("tcp", address)

	if err != nil {
		fmt.Println("Error Connecting:", err)
		os.Exit(1)
	}
	defer conn.Close()

}
