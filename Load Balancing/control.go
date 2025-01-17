package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
		task := <-queue
		a := task.a
		b := task.b
		c := task.c

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
		fmt.Printf("Result (conn %d): %f | %.3f seconds\n", id, res, elapsed.Seconds())
	}

	println("Worker Disconnected")
}

var queue chan *Task

type Task struct {
	a float32
	b float32
	c float32
}

func main() {
	println("Control Started")

	size := 100
	queue = make(chan *Task, size)

	for i := 0; i < size; i++ {
		var task Task
		task.a = 200 + rand.Float32()*(150)
		task.b = 100 + rand.Float32()*(80)
		task.c = 1 + rand.Float32()*(0.1)

		queue <- &task
	}

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
		workers++
	}
}
