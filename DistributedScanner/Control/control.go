//go:build a

package main

import (
	utils "DistributedScanner/Utils"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

var queue chan *utils.Task
var serverLog *os.File

const NIPS_PER_TASK = 256
const TASK_MASK = 24

func handleConnection(conn net.Conn, id int, password []byte) {
	defer conn.Close()
	fmt.Println("Worker connected")

	var task *utils.Task
	var status int = 0
	var log string = fmt.Sprintf("Worker %d connected\n", id)

	for {
		startTime := time.Now()
		log += fmt.Sprintf("\tDate [%s]\n", startTime.Format("2006-01-02 15:04:05"))

		// exit out if finished
		if len(queue) == 0 {
			log += "\tOut of tasks\n"
			status = 0
			break
		}

		// establish rsa with connection
		privateKey, _, connPubKey, err := utils.RSAHandshake(conn)
		if err != nil {
			log += fmt.Sprintf("\tError performing RSA handshake: %s\n\n", err.Error())
			status = 1
			break
		}

		handshakeTime := time.Since(startTime)
		log += fmt.Sprintf("\tRSA Handshake [%f seconds]\n", handshakeTime.Seconds())

		// grab a task from the queue
		task = <-queue
		log += fmt.Sprintf("\tSending task to worker:\n\t\tIpv4: %s\n\t\tMask: %d\n\t\tScanner: %d\n\t\tArgs: %s\n",
			utils.UnpackIP(task.Ipv4), task.Mask, task.Scanner, task.Args)

		// add expire time
		task.Expires = time.Now().Add(time.Minute)

		// serialize task into binary
		plaintext := utils.SerializeStruct(task)

		// send task to connection
		err = utils.SendMessage(conn, plaintext, password, privateKey, connPubKey)
		if err != nil {
			log += fmt.Sprintf("\tError sending task to worker: %s\n\n", err.Error())
			status = 1
			break
		}

		// recieve results from connection
		resultBytes, err := utils.RecieveMessage(conn, password, privateKey, connPubKey)
		if err != nil {
			log += fmt.Sprintf("\tError recieving message from worker: %s\n\n", err.Error())
			status = 1
			break
		}

		results, err := utils.DeserializeResult(resultBytes)
		if err != nil {
			log += fmt.Sprintf("\tError parsing result struct: %s\n\n", err.Error())
			status = 1
			break
		}

		elapsed := time.Since(startTime)
		log += fmt.Sprintf("\tScan Complete [%f seconds]\n\tConnection Complete [%f seconds]\n\n", results.ScanTime, elapsed.Seconds())
	}

	// if there was an error during execution, add the most recent task back to the queue
	if status == 1 {
		log += fmt.Sprintf("\tAdding task to queue:\n\t\tIpv4: %s\n\t\tMask: %d\n\t\tScanner: %d\n\t\tArgs: %s\n",
			utils.UnpackIP(task.Ipv4), task.Mask, task.Scanner, task.Args)
		queue <- task
	}

	fmt.Println("Worker Disconnected")
	log += fmt.Sprintf("Worker %d disconnected\n\n", id)
	serverLog.WriteString(log)
}

func startDistribution(passwordHash []byte) {
	port := "1234"
	address := "localhost:" + port

	// listen on defined port and address
	listener, err := net.Listen("tcp", address)
	if err != nil {
		println("Error setting up socket")
		os.Exit(1)
	}
	defer listener.Close()

	// accept incoming connections and pass them off to be handled
	workers := 0
	for {
		conn, err := listener.Accept()
		if err != nil {
			println("Error accepting connection")
			continue
		}

		go handleConnection(conn, workers, passwordHash)
		workers++
	}
}

func main() {
	// server log
	serverLog, _ = os.OpenFile("serverlog.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

	// set up args
	scannerArgs := flag.String("args", "", "Send args to scanner")

	flag.Parse()
	args := flag.Args()

	if len(args) < 2 {
		os.Exit(1)
	}

	iprange := args[0]
	password := utils.Hash([]byte(args[1]))

	ip, subnet, _ := net.ParseCIDR(iprange)
	subnetMask, _ := subnet.Mask.Size()

	// ip range we're covering, network being start ip and broadcast being end ip
	var broadcast uint32 = 1 << (32 - uint(subnetMask))
	var network uint32 = utils.PackIP(ip)

	// set up for number of tasks we need
	var nips uint32 = broadcast - network
	var ntasks int = max(int(nips)/NIPS_PER_TASK, 1)
	queue = make(chan *utils.Task, ntasks)

	fmt.Println("Scanning", nips, "IP(s) | Generating", ntasks, "task(s)")
	for i := 0; i < ntasks; i++ {
		var task utils.Task
		task.Ipv4 = uint32(i * NIPS_PER_TASK)
		task.Mask = TASK_MASK
		task.Scanner = 0
		task.Args = *scannerArgs

		// add task to queue
		queue <- &task
	}

	// start listening for worker threads
	startDistribution(password)
}
