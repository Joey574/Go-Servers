package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"net"
)

func PackIP(ip net.IP) uint32 {
	return uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15])
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
