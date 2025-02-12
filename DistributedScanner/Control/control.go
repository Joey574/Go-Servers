//go:build a

package main

import (
	rsaUtils "DistributedScanner/Utils"
	"bytes"
	"encoding/gob"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

type Task struct {
	Ipv4    uint32
	Mask    uint32
	Scanner uint8
	Args    string
}

var queue chan *Task

const NIPS_PER_TASK = 4096
const TASK_MASK = 20

const CIPHERTEXT = "Ciphertext\n"
const SIGNATURE = "\nSignature\n"

func packIP(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
func unpackIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24&0xff), byte(ip>>16&0xff), byte(ip>>8&0xff), byte(ip&0xff))
}

func handleConnection(conn net.Conn, id int) {
	defer conn.Close()
	fmt.Println("Worker connected")

	for {
		startTime := time.Now()

		// establish rsa with connection
		privateKey, _, connPubKey, err := rsaUtils.RSAHandshake(conn)
		if err != nil {
			fmt.Println("Error performing RSA handshake")
			break
		}

		// grab a task from the queue
		task := <-queue

		// convert Task struct to []bytes
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		enc.Encode(task)
		plaintext := buf.Bytes()

		// send task to connection
		err = rsaUtils.SendMessage(conn, plaintext, privateKey, connPubKey)
		if err != nil {
			fmt.Println("Error sending task to worker")
			break
		}

		// recieve results from connection
		results, err := rsaUtils.RecieveMessage(conn, privateKey, connPubKey)
		if err != nil {
			fmt.Println("Error recieving message from worker")
			break
		}
		fmt.Println("\nResults:\n", string(results))

		elapsed := time.Since(startTime)
		fmt.Println("Task completed in ", elapsed.Seconds(), " seconds")
	}

	fmt.Println("Worker Disconnected")
}

func startDistribution() {
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

		go handleConnection(conn, workers)
		workers++
	}
}

func main() {

	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		os.Exit(1)
	}

	iprange := args[0]

	ip, subnet, _ := net.ParseCIDR(iprange)
	subnetMask, _ := subnet.Mask.Size()

	// ip range we're covering, network being start ip and broadcast being end ip
	var broadcast uint32 = 1 << (32 - uint(subnetMask))
	var network uint32 = packIP(ip)

	// nips = number of ips we're covering, ntasks is the number of tasks we need to dispatch
	var nips uint32 = broadcast - network
	var ntasks int = max(int(nips)/NIPS_PER_TASK, 1)
	queue = make(chan *Task, ntasks)

	fmt.Println("Scanning ", nips, " IP(s) | Generating ", ntasks, " task(s)")
	for i := 0; i < ntasks; i++ {
		var task Task
		task.Ipv4 = uint32(i * NIPS_PER_TASK)
		task.Mask = TASK_MASK
		task.Scanner = 0
		task.Args = "-sn --min-parallelism 100"

		// add task to queue
		queue <- &task
	}

	// start listening for worker threads
	startDistribution()
}
