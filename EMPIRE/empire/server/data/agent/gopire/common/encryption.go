package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

func AesEncryptThenHMAC(key, data []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	padSize := aes.BlockSize - len(data)%aes.BlockSize
	padding := bytes.Repeat([]byte{byte(padSize)}, padSize)
	data = append(data, padding...)

	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)

	ciphertext = append(iv, ciphertext...)

	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)
	hmacValue := h.Sum(nil)[:10]

	finalData := append(ciphertext, hmacValue...)
	return finalData
}

func verifyHMAC(key, data []byte) bool {
	if len(data) <= 10 {
		return false
	}

	mac := data[len(data)-10:]
	data = data[:len(data)-10]

	expectedMAC := hmac.New(sha256.New, key)
	expectedMAC.Write(data)
	expectedMACDigest := expectedMAC.Sum(nil)[:10]

	// fmt.Printf("Data: %x\n", data)
	// fmt.Printf("MAC: %x\n", mac)
	// fmt.Printf("Expected MAC: %x\n", expectedMACDigest)

	return hmac.Equal(mac, expectedMACDigest)
}

func AesDecryptAndVerify(key, data []byte) ([]byte, error) {
	if !verifyHMAC(key, data) {
		return nil, fmt.Errorf("invalid ciphertext received")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize : len(data)-10]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	padding := int(ciphertext[len(ciphertext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	for _, padByte := range ciphertext[len(ciphertext)-padding:] {
		if int(padByte) != padding {
			return nil, fmt.Errorf("invalid padding byte")
		}
	}

	return ciphertext[:len(ciphertext)-padding], nil
}
