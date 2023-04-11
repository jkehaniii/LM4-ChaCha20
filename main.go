package main

// https://asecuritysite.com/encryption/go_chacha

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
)

func main() {

	// Takes message and passphrase
	fmt.Println("Enter Your Message: ")
	var input string
	fmt.Scanln(&input)
	msg := input
	pass := "Hello"

	// Generates keys for encryption
	key := sha256.Sum256([]byte(pass))
	aead, _ := chacha20poly1305.NewX(key[:])

	if pass == "" {
		a := make([]byte, 32)
		copy(key[:32], a[:32])
		aead, _ = chacha20poly1305.NewX(a)
	}
	if msg == "" {
		a := make([]byte, 32)
		msg = string(a)
	}
	// Encrypts
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	ciphertext := aead.Seal(nil, nonce, []byte(msg), nil)

	// Decrypts
	plaintext, _ := aead.Open(nil, nonce, ciphertext, nil)

	// Formatted output of all info
	fmt.Printf("Message:\t%s\n", msg)
	fmt.Printf("Passphrase:\t%s\n", pass)
	fmt.Printf("\nKey:\t%x\n", key)
	fmt.Printf("Nonce:\t%x\n", nonce)
	fmt.Printf("\nCipher stream:\t%x\n", ciphertext)
	fmt.Printf("Plain text:\t%s\n", plaintext)
}
