//go:build a

package main

import (
	utils "DistributedScanner/Utils"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/peterh/liner"
)

var serverLog *os.File

func main() {
	// server log
	serverLog, _ = os.OpenFile("serverlog.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Please input a password")
		os.Exit(1)
	}

	state := &utils.State{
		StatusCode:   utils.STATUS_PAUSE,
		TaskQueue:    make(chan *utils.Task, 100),
		ResultQueue:  make(chan *utils.Result, 100),
		PasswordHash: utils.Hash([]byte(args[0])),
	}

	go startDistribution(state)
	inputHandler(state)
}

func inputHandler(state *utils.State) {
	// Setup liner for CLI input
	line := liner.NewLiner()
	defer line.Close()

	line.SetCtrlCAborts(true)
	line.SetCompleter(func(line string) []string {
		return []string{"status", "pause", "resume", "quit", "task", "taskall", "scantask"}
	})

	// interupt signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// loop
	for {
		select {
		case <-sigCh:
			state.StatusCode = utils.STATUS_SHUTDOWN
			return
		default:
			if input, err := line.Prompt("> "); err == nil {
				line.AppendHistory(input)
				processCommand(input, state)
			} else if err == liner.ErrPromptAborted {
				return
			} else {
				fmt.Printf("Input error: %v\n", err)
			}
		}
	}
}
func processCommand(input string, state *utils.State) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}
	//  supported commands {"status", "pause", "resume", "quit", "task", "taskall", "scantask"}
	switch parts[0] {
	case "status":

	case "pause":
		state.Lock()
		state.StatusCode = utils.STATUS_PAUSE
		state.Unlock()
		fmt.Println("Execution paused")

	case "resume":
		state.Lock()
		state.StatusCode = utils.STATUS_CONTINUE
		state.Unlock()
		fmt.Println("Execution resumed")

	case "quit":
		state.Lock()
		state.StatusCode = utils.STATUS_SHUTDOWN
		state.Unlock()
		fmt.Println("Shutting down")

	case "task":
		if len(parts) < 2 {
			fmt.Println("Usage: task <cmd> <cmdArgs>")
			return
		}

		utils.InputAddTask(state, parts)

	case "taskall":
		if len(parts) < 2 {
			fmt.Println("Usage: taskall <cmd> <cmdArgs>")
			return
		}

		utils.InputAddAllTask(state, parts)

	case "scantask":
		if len(parts) < 3 {
			fmt.Println("Usage: scantask <iprange> <cmd> <cmdArgs>")
			return
		}

		utils.InputAddScanTask(state, parts)

	default:
		fmt.Println("Unknown command. Available: status, pause, resume, quit, task, taskall, scantask")
	}
}

func startDistribution(state *utils.State) {
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

		go handleConnection(conn, workers, state)
		workers++
	}
}
func handleConnection(conn net.Conn, id int, state *utils.State) {
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
		err = utils.SendMessage(conn, plaintext, state.PasswordHash, privateKey, connPubKey)
		if err != nil {
			log += fmt.Sprintf("\tError sending task to worker: %s\n\n", err.Error())
			status = 1
			break
		}

		// recieve results from connection
		resultBytes, err := utils.RecieveMessage(conn, state.PasswordHash, privateKey, connPubKey)
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

		state.ResultQueue <- &results
		elapsed := time.Since(startTime)
		log += fmt.Sprintf("\tScan Complete [%f seconds]\n\tConnection Complete [%f seconds]\n\n", results.CmdTime, elapsed.Seconds())
	}

	// if there was an error during execution, add the most recent task back to the queue
	if status == 1 {
		log += fmt.Sprintf("\tAdding task to queue:\n\t\tStatus: %d\n\t\tCommand: %s\n\t\tArgs: %s\n", task.Status, task.Cmd, task.Args)
		state.TaskQueue <- task
	}

	fmt.Println("Worker Disconnected")
	log += fmt.Sprintf("Worker %d disconnected\n\n", id)
	serverLog.WriteString(log)
}

func formatTask(task *utils.Task) *utils.Task {
	// if len(taskQueue) > 0 {
	// 	task = <-taskQueue
	// 	task.Status = utils.EXEC_TASK
	// } else {
	// 	task.Status = utils.EXIT_TASK
	// }

	// task.Expires = time.Now().Add(time.Minute)
	return task
}
