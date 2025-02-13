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

const NIPS_PER_TASK uint32 = 256
const TASK_MASK = 24

var taskQueue chan *utils.Task
var resultQueue chan *utils.Result

var serverLog *os.File

func formatTask(task *utils.Task) *utils.Task {
	if len(taskQueue) > 0 {
		task = <-taskQueue
		task.Status = utils.EXEC_TASK
	} else {
		task.Status = utils.EXIT_TASK
	}

	task.Expires = time.Now().Add(time.Minute)
	return task
}

func handleConnection(conn net.Conn, id int, password []byte) {
	defer conn.Close()
	fmt.Println("Worker connected")

	var task *utils.Task = &utils.Task{}
	var status int = 0
	var log string = fmt.Sprintf("Worker %d connected\n", id)

	for {
		startTime := time.Now()
		log += fmt.Sprintf("\tDate [%s]\n", startTime.Format("2006-01-02 15:04:05"))

		// establish rsa with connection
		privateKey, _, connPubKey, err := utils.RSAHandshake(conn)
		if err != nil {
			log += fmt.Sprintf("\tError performing RSA handshake: %s\n\n", err.Error())
			status = 1
			break
		}

		handshakeTime := time.Since(startTime)
		log += fmt.Sprintf("\tRSA Handshake [%f seconds]\n", handshakeTime.Seconds())

		// get task
		task = formatTask(task)
		log += fmt.Sprintf("\tSending task to worker:\n\t\tStatus: %d\n\t\tCommand: %s\n\t\tArgs: %s\n", task.Status, task.Cmd, task.Args)

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

		resultQueue <- &results
		elapsed := time.Since(startTime)
		log += fmt.Sprintf("\tScan Complete [%f seconds]\n\tConnection Complete [%f seconds]\n\n", results.CmdTime, elapsed.Seconds())
	}

	// if there was an error during execution, add the most recent task back to the queue
	if status == 1 {
		log += fmt.Sprintf("\tAdding task to queue:\n\t\tCommand: %s\n\t\tArgs: %s\n", task.Cmd, task.Args)
		taskQueue <- task
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

func monitorState(ntasks uint32) {
	for {
		if uint32(len(resultQueue)) == ntasks {
			var final string = "Tasks complete:\n"

			for i := 0; len(resultQueue) != 0; i++ {
				result := <-resultQueue
				final += fmt.Sprintf("Result:\n%s\nTime: %f\n", result.CmdResult, result.CmdTime)
			}

			fmt.Print(final)
			break
		} else {
			time.Sleep(time.Second)
		}
	}
}

func main() {
	// server log
	serverLog, _ = os.OpenFile("serverlog.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

	// set up args
	cmd := flag.String("cmd", "", "Command to execute")
	cmdArgs := flag.String("args", "", "Arguments to pass to command")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <ip_range> <password>\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Arguments:")
		fmt.Fprintln(os.Stderr, "  ip_range:   The IP range to scan")
		fmt.Fprintln(os.Stderr, "  password:   The password to verify worker connection")
		flag.PrintDefaults()
	}

	flag.Parse()
	args := flag.Args()

	if len(args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	iprange := args[0]
	password := utils.Hash([]byte(args[1]))

	ip, subnet, _ := net.ParseCIDR(iprange)
	subnetMask, _ := subnet.Mask.Size()

	// ip range we're covering, network being start ip and broadcast being end ip
	var network uint32 = utils.PackIP(ip)
	mask := ip.DefaultMask()
	var umask uint32 = (uint32(mask[0]) << 24) | (uint32(mask[1]) << 16) | (uint32(mask[2]) << 8) | uint32(mask[3])
	network = network & umask
	var broadcast uint32 = 1<<(32-uint(subnetMask)) + network

	// set up for number of tasks we need
	var nips uint32 = broadcast - network
	var ntasks uint32 = max(nips/NIPS_PER_TASK, 1)

	taskQueue = make(chan *utils.Task, ntasks)
	resultQueue = make(chan *utils.Result, ntasks)

	fmt.Println("Scanning", nips, "IP(s) | Generating", ntasks, "task(s)")
	for i := uint32(0); i < ntasks; i++ {
		var task utils.Task
		task.Cmd = *cmd
		task.Args = *cmdArgs + fmt.Sprintf(" %s/%d", utils.UnpackIP((i*NIPS_PER_TASK)+network), TASK_MASK)

		// add task to queue
		taskQueue <- &task
	}

	// monitor state of program and handle output and storage
	go monitorState(ntasks)

	// start listening for worker threads
	startDistribution(password)
}
