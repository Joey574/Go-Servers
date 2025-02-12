package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

type Task struct {
	ipv4    uint32
	mask    uint32
	scanner uint8
	args    string
}

var queue chan *Task

const RSA_KEY_SIZE = 2048
const NIPS_PER_TASK = 4096
const TASK_MASK = 20

func packIP(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
func unpackIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24&0xff), byte(ip>>16&0xff), byte(ip>>8&0xff), byte(ip&0xff))
}

func generateRSAKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func encryptRSA(publicKey *rsa.PublicKey, data []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}
func decryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func signData(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(data)
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
func verifySignature(publicKey *rsa.PublicKey, message, signature []byte) error {
	hash := sha256.New()
	hash.Write(message)
	hashed := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signature)
}

func RSAHandshake(conn net.Conn) (*rsa.PrivateKey, *rsa.PublicKey, *rsa.PublicKey, error) {
	// generate 2048 bit rsa keys
	privateKey, publicKey, err := generateRSAKeys(RSA_KEY_SIZE)
	if err != nil {
		return nil, nil, nil, err
	}

	// send public key to connection
	encPubKey := x509.MarshalPKCS1PublicKey(publicKey)
	_, err = conn.Write(encPubKey)
	if err != nil {
		fmt.Println("Error sending public key:", err)
		return nil, nil, nil, err
	}

	// recieve public key from connection
	connPubKeyBytes := make([]byte, RSA_KEY_SIZE)
	_, err = conn.Read(connPubKeyBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	// decode conn pubkey
	connPubKey, err := x509.ParsePKCS1PublicKey(connPubKeyBytes)

	return privateKey, &privateKey.PublicKey, connPubKey, nil
}

func handleConnection(conn net.Conn, id int) {
	defer conn.Close()
	fmt.Println("Worker Connected")

	//recvbuf := make([]byte, 4)

	for {
		startTime := time.Now()

		// establish rsa with connection
		privateKey, publicKey, _, err := RSAHandshake(conn)
		if err != nil {
			fmt.Println("Error performing RSA handshake")
			return
		}

		// grab a task from the queue
		task := <-queue

		// convert data to []bytes
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		enc.Encode(task)
		plaintext := buf.Bytes()

		// encrypt task
		ciphertext, err := encryptRSA(publicKey, plaintext)
		if err != nil {
			return
		}

		// generate signature
		signature, _ := signData(privateKey, plaintext)

		// send full message to connection
		message := append(append(append([]byte("Ciphertext\n"), ciphertext...), []byte("\nSignature\n")...), signature...)
		conn.Write(message)

		elapsed := time.Since(startTime)
		fmt.Println(elapsed.Seconds())
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
		task.ipv4 = uint32(i * NIPS_PER_TASK)
		task.mask = TASK_MASK
		task.scanner = 0
		task.args = ""

		// add task to queue
		queue <- &task
	}

	// start listening for worker threads
	startDistribution()
}
