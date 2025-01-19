//go:build b

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"time"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()

	recvbuf := make([]byte, 12)

	for {
		_, err := conn.Read(recvbuf)
		if err != nil {
			break
		}

		startTime := time.Now()

		ua := binary.BigEndian.Uint32(recvbuf[:4])
		ub := binary.BigEndian.Uint32(recvbuf[4:8])
		uc := binary.BigEndian.Uint32(recvbuf[8:12])

		a := float32(ua)
		b := float32(ub)
		c := float32(uc)

		res := float32(0.0)

		for range 100000000 {
			res += (a / b) * c

			a *= (c / b) + a
			b *= (b * c) / a
			c /= b + c

			a *= float32(math.Sin(float64(b)))
			b *= float32(math.Cos(float64(a)))
			c = float32(math.Sin(float64(c)))

			res = float32(math.Sin(float64(res)))

			a = 200 + rand.Float32()*(150)
			b = 100 + rand.Float32()*(80)
			c = 1 + rand.Float32()*(0.1)
		}

		res /= (res - a) / b
		res = float32(math.Cos(float64(res)))

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, res)

		elapsed := time.Since(startTime)
		fmt.Printf("Task completed: %.3f seconds\n", elapsed.Seconds())

		_, err = conn.Write(buf.Bytes())
		if err != nil {
			break
		}
	}

	println("Host Disconnected")
}

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

	handleConnection(conn)
}
