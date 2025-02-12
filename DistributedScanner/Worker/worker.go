//go:build b

package main

import (
	rsaUtils "DistributedScanner/Utils"
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Task struct {
	Ipv4    uint32
	Mask    uint32
	Scanner uint8
	Args    string
}

const CIPHERTEXT = "Ciphertext\n"
const SIGNATURE = "\nSignature\n"

func executeTask(task Task) ([]byte, error) {
	cmd := "nmap"
	args := strings.Fields(task.Args)

	fmt.Println("Executing: ", cmd, " with args: ", args)
	scan := exec.Command(cmd, args...)

	output, err := scan.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return output, nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		startTime := time.Now()

		// establish rsa with server
		privateKey, _, connPubKey, err := rsaUtils.RSAHandshake(conn)
		if err != nil {
			fmt.Println("Error performing RSA handshake", err.Error())
			break
		}

		// recieve plaintext from connection
		plaintext, err := rsaUtils.RecieveMessage(conn, privateKey, connPubKey)
		if err != nil {
			fmt.Println("Error recieving task from control")
			break
		}

		// read data into task struct
		var task Task
		dec := gob.NewDecoder(bytes.NewReader(plaintext))
		err = dec.Decode(&task)
		if err != nil {
			fmt.Println("Error reading into Task")
			break
		}

		// execute the task
		results, err := executeTask(task)
		if err != nil {
			fmt.Println("Error executing task")
			break
		}

		// send message to control
		err = rsaUtils.SendMessage(conn, results, privateKey, connPubKey)
		if err != nil {
			fmt.Println("Error sending message to control")
			break
		}

		elapsed := time.Since(startTime)
		fmt.Println("Task completed in ", elapsed.Seconds(), " seconds")
	}
}

func main() {
	fmt.Println("Worker Started")

	ipAddress := "127.0.0.1"
	port := "1234"
	address := ipAddress + ":" + port

	conn, err := net.Dial("tcp", address)

	if err != nil {
		fmt.Println("Error connecting to server:", err)
		os.Exit(1)
	}

	handleConnection(conn)
	fmt.Println("Worker Exiting")
}
