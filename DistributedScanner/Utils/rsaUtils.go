package rsaUtils

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"net"
	"strings"
)

const CIPHERTEXT = "Ciphertext\n"
const SIGNATURE = "\nSignature\n"

const RSA_KEY_SIZE = 2048

func GenerateRSAKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func EncryptRSA(publicKey *rsa.PublicKey, data []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}
func DecryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func SignData(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(data)
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
func VerifySignature(publicKey *rsa.PublicKey, message, signature []byte) error {
	hash := sha256.New()
	hash.Write(message)
	hashed := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signature)
}

func RSAHandshake(conn net.Conn) (*rsa.PrivateKey, *rsa.PublicKey, *rsa.PublicKey, error) {
	// generate 2048 bit rsa keys
	privateKey, publicKey, err := GenerateRSAKeys(RSA_KEY_SIZE)
	if err != nil {
		return nil, nil, nil, err
	}

	// send public key to connection
	encPubKey := x509.MarshalPKCS1PublicKey(publicKey)
	_, err = conn.Write(encPubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// recieve public key from connection
	connPubKeyBytes := make([]byte, len(encPubKey))
	_, err = conn.Read(connPubKeyBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	// decode conn pubkey
	connPubKey, err := x509.ParsePKCS1PublicKey(connPubKeyBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return privateKey, &privateKey.PublicKey, connPubKey, nil
}

func SendMessage(conn net.Conn, message []byte, privateKey *rsa.PrivateKey, connPubKey *rsa.PublicKey) error {

	// encrypt results
	ciphertext, err := EncryptRSA(connPubKey, message)
	if err != nil {
		return err
	}

	// sign results
	signature, err := SignData(privateKey, message)
	if err != nil {
		return err
	}

	// format message
	lenbuf := new(bytes.Buffer)
	formatted := append(append(append([]byte(CIPHERTEXT), ciphertext...), []byte(SIGNATURE)...), signature...)
	binary.Write(lenbuf, binary.BigEndian, uint32(len(formatted)))

	// send message length and message
	conn.Write(lenbuf.Bytes())
	conn.Write(formatted)
	if err != nil {
		return err
	}

	return nil
}
func RecieveMessage(conn net.Conn, privateKey *rsa.PrivateKey, connPubKey *rsa.PublicKey) ([]byte, error) {
	// get message length
	lenbuf := make([]byte, 4)
	var mlen uint32

	_, err := conn.Read(lenbuf)
	if err != nil {
		return nil, err
	}

	// convert to uint32
	tbuf := bytes.NewReader(lenbuf)
	binary.Read(tbuf, binary.BigEndian, &mlen)

	// read actual message
	buf := make([]byte, mlen)
	_, err = conn.Read(buf)
	if err != nil {
		return nil, err
	}

	// parse the message
	message := string(buf)

	ctIdx := strings.Index(message, CIPHERTEXT)
	sigIdx := strings.Index(message, SIGNATURE)
	if ctIdx == -1 || sigIdx == -1 {
		return nil, err
	}

	// parse ciphertext and signature
	ctIdx += len(CIPHERTEXT)
	ciphertext := message[ctIdx:sigIdx]

	sigIdx += len(SIGNATURE)
	signature := message[sigIdx:]

	// decrypt message
	plaintext, err := DecryptRSA(privateKey, []byte(ciphertext))
	if err != nil {
		return nil, err
	}

	// verify signature
	err = VerifySignature(connPubKey, []byte(plaintext), []byte(signature))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
