//go:build b

package main

import (
	utils "DistributedScanner/Utils"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func executeTask(task utils.Task) ([]byte, error) {
	cmd := task.Cmd
	args := strings.Fields(task.Args)

	fmt.Println("Executing: ", cmd, args)
	scan := exec.Command(cmd, args...)

	output, err := scan.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return output, nil
}

func handleConnection(conn net.Conn, password []byte) {
	defer conn.Close()

	for {
		// establish rsa with server
		privateKey, _, connPubKey, err := utils.RSAHandshake(conn)
		if err != nil {
			fmt.Println("Error performing RSA handshake", err.Error())
			break
		}

		// recieve plaintext from connection
		plaintext, err := utils.RecieveMessage(conn, password, privateKey, connPubKey)
		if err != nil {
			fmt.Println("Error recieving task from control:", err.Error())
			break
		}

		// read data into task struct
		task, err := utils.DeserializeTask(plaintext)
		if err != nil {
			fmt.Println("Error deserializing task")
			break
		}

		// execute the task
		if task.Status == utils.STATUS_CONTINUE {
			startTime := time.Now()
			scanString, err := executeTask(task)
			if err != nil {
				fmt.Println("Error executing task:", err.Error())
				break
			}
			elapsed := time.Since(startTime)

			// form results struct
			var results utils.Result
			results.CmdResult = string(scanString)
			results.CmdTime = float32(elapsed.Seconds())

			// serialize
			message := utils.SerializeStruct(results)

			// send message to control
			err = utils.SendMessage(conn, message, password, privateKey, connPubKey)
			if err != nil {
				fmt.Println("Error sending message to control:", err.Error())
				break
			}
		} else if task.Status == utils.STATUS_SHUTDOWN {
			break
		}

	}
}

func main() {
	fmt.Println("Worker Started")

	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		os.Exit(1)
	}

	password := utils.Hash([]byte(args[0]))

	ipAddress := "127.0.0.1"
	port := "1234"
	address := ipAddress + ":" + port

	conn, err := net.Dial("tcp", address)

	if err != nil {
		fmt.Println("Error connecting to server:", err)
		os.Exit(1)
	}

	handleConnection(conn, password)
	fmt.Println("Worker Exiting")
}
