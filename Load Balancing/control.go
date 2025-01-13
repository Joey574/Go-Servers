package main

import (
	"net"
	"os"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()

	println("Handling connection")
}

func main() {
	println("Control Started")

	port := "1234"
	address := "localhost:" + port

	listener, err := net.Listen("tcp", address)
	if err != nil {
		println("Error setting up socket")
		os.Exit(1)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			println("Error accepting connection")
			continue
		}

		go handleConnection(conn)
	}
}
