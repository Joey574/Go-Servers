package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"net"
	"time"
)

type Task struct {
	Ipv4    uint32
	Mask    uint32
	Scanner uint8
	Args    string
	Expires time.Time
}

type Result struct {
	ScanResult string
	ScanTime   float32
}

func PackIP(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
func UnpackIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24&0xff), byte(ip>>16&0xff), byte(ip>>8&0xff), byte(ip&0xff))
}

func Hash(plaintext []byte) []byte {
	hash := sha256.New()
	hash.Write(plaintext)
	hashBytes := hash.Sum(nil)

	return hashBytes
}

func SerializeStruct(data any) []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(data)
	bytes := buf.Bytes()

	return bytes

}

func DeserializeTask(data []byte) (Task, error) {
	var task Task
	dec := gob.NewDecoder(bytes.NewReader(data))

	err := dec.Decode(&task)
	if err != nil {
		return Task{}, err
	}

	return task, nil
}
func DeserializeResult(data []byte) (Result, error) {
	var result Result
	dec := gob.NewDecoder(bytes.NewReader(data))

	err := dec.Decode(&result)
	if err != nil {
		return Result{}, err
	}

	return result, nil
}
