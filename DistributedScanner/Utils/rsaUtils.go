package utils

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
)

const RSA_KEY_SIZE = 4096

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
	// generate rsa keys
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

func SendMessage(conn net.Conn, plaintext []byte, password []byte, privateKey *rsa.PrivateKey, connPubKey *rsa.PublicKey) error {
	/*
		Message Format:
			[RSA Signature]
			[RSA] password hash
			[RSA] AES key
			[RSA] Ciphertext length
			[AES] Ciphertext
	*/

	// generate aes key
	aesKey, err := GenerateAESKey()
	if err != nil {
		return err
	}

	// encrypt message with aes key
	ciphertext, err := EncryptAES(aesKey, plaintext)
	if err != nil {
		return err
	}

	// get length of ciphertext
	ctlenbuf := new(bytes.Buffer)
	binary.Write(ctlenbuf, binary.BigEndian, uint32(len(ciphertext)))

	// format data to be RSA encrypted
	rsaData := append(append(password, aesKey...), ctlenbuf.Bytes()...)

	rsaCiphertext, err := EncryptRSA(connPubKey, rsaData)
	if err != nil {
		return err
	}

	// format message
	message := append(rsaCiphertext, ciphertext...)

	// sign message
	signature, err := SignData(privateKey, message)
	if err != nil {
		return err
	}

	// prepend signature
	message = append(signature, message...)

	// send message
	_, err = conn.Write(message)
	if err != nil {
		return err
	}

	return nil
}
func RecieveMessage(conn net.Conn, password []byte, privateKey *rsa.PrivateKey, connPubKey *rsa.PublicKey) ([]byte, error) {
	/*
		Message Format:
			[RSA Signature]
			[RSA] password hash
			[RSA] AES key
			[RSA] Ciphertext length
			[AES] Ciphertext
	*/

	// get RSA Signature
	signature := make([]byte, RSA_KEY_SIZE/8)
	_, err := conn.Read(signature)
	if err != nil {
		return nil, err
	}

	// get RSA encrypted data
	rsaCiphertext := make([]byte, RSA_KEY_SIZE/8)
	_, err = conn.Read(rsaCiphertext)
	if err != nil {
		return nil, err
	}

	rsaData, err := DecryptRSA(privateKey, rsaCiphertext)
	if err != nil {
		return nil, err
	}

	recvPassword := rsaData[:32]
	aesKey := rsaData[32:64]
	ctLenBytes := rsaData[64:68]

	if string(recvPassword) != string(password) {
		return nil, fmt.Errorf("password hashes do not match")
	}

	// convert to uint32
	var ctlen uint32
	tbuf := bytes.NewReader(ctLenBytes)
	binary.Read(tbuf, binary.BigEndian, &ctlen)

	// read ciphertext
	ctbuf := make([]byte, ctlen)
	_, err = conn.Read(ctbuf)
	if err != nil {
		return nil, err
	}

	// verify message signature
	formatted := append(rsaCiphertext, ctbuf...)
	err = VerifySignature(connPubKey, formatted, signature)
	if err != nil {
		return nil, fmt.Errorf("message signature invalid")
	}

	// decrypt message
	plaintext, err := DecryptAES(aesKey, ctbuf)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
