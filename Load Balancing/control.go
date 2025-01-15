//go:build a

package main

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"os"
	"time"
)

func handleConnection(conn net.Conn, id int) {
	defer conn.Close()
	println("Worker Connected")

	recvbuf := make([]byte, 4)

	for {
		a := 200 + rand.Float32()*(150)
		b := 100 + rand.Float32()*(80)
		c := 1 + rand.Float32()*(0.1)

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, a)
		binary.Write(buf, binary.BigEndian, b)
		binary.Write(buf, binary.BigEndian, c)

		startTime := time.Now()

		_, err := conn.Write(buf.Bytes())
		if err != nil {
			break
		}
		_, err = conn.Read(recvbuf)
		if err != nil {
			break
		}

		elapsed := time.Since(startTime)

		recvval := binary.BigEndian.Uint32(recvbuf)
		res := float32(recvval)
		print("Result (conn ", id, "): ", res, " | ", elapsed.Seconds(), " seconds\n")
	}

	println("Worker Disconnected")
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

	workers := 0
	for {
		conn, err := listener.Accept()
		if err != nil {
			println("Error accepting connection")
			continue
		}

		go handleConnection(conn, workers)
		workers += 1
	}
}
