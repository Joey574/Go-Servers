package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func GenerateAESKey() ([]byte, error) {
	key := make([]byte, AES_KEY_SIZE/8)
	_, err := rand.Read(key)

	if err != nil {
		return nil, err
	}

	return key, nil
}

func EncryptAES(key []byte, plaintext []byte) ([]byte, error) {

	// create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	iv := make([]byte, blockSize)

	// set up iv
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	// encrypt plaintext
	stream := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// prepend iv and return
	ciphertext = append(iv, ciphertext...)
	return ciphertext, nil
}

func DecryptAES(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(ciphertext) < blockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
