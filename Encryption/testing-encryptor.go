/*
Author: hxhBrofessor
Purpose: AES encrypts the file's contents and has two functions generating different outputs.
      Output1 is plaintext.bin, the original unencrypted format the program ingested initially. Output 2 is a byte array in the format of
      "0x16, 0xbf, 0x7f, 0xa4, 0xda, 0x94, 0x41, 0x5b, 0x27".

      Output two can be used as a byte array to execute the unencrypted shellcode.

	EXAMPLE: // encrypted shellcode - output of aes_shellcode_encrypter.go
    e := []byte{0x16, 0xbf, 0x7f, 0xa4, 0xda, 0x94, 0x41, 0x5b, 0x27, 0x47, 0x53, 0xbb, 0x9b, 0xb1, 0x32}
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {

	encryptFile()
	//decryptFile() //unencrypts the file
	//decryptFile2()
}

func encryptFile() {
	// Reading plaintext file
	file, err := os.Open("calc.bin")
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	plainText, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Creating key
	key := []byte("xL3gGa4RM$S@LsSY")

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating cipher block: %v", err)
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM: %v", err)
	}

	// Generating random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("Error generating nonce: %v", err)
	}

	// Encrypt file
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	// Writing ciphertext file
	//file, err = os.Create("ENC.bin")
	file, err = os.Create("2ENC.bin") //this will contain the encrypted data as a byte array
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer file.Close()

	_, err = file.Write(cipherText)
	if err != nil {
		log.Fatalf("Error writing file: %v", err)
	}
}

func decryptFile() {
	// Reading ciphertext file
	file, err := os.Open("ENC.bin")
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	cipherText, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Creating key
	key := []byte("xL3gGa4RM$S@LsSY")

	// Creating block of algorithm
	block, err := aes.NewCipher(
		key)
	if err != nil {
		log.Fatalf("Error creating cipher block: %v", err)
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM: %v", err)
	}

	// Deattached nonce and decrypt
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("Error decrypting file: %v", err)
	}

	// Writing decryption content
	file, err = os.Create("plaintext.bin")
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer file.Close()

	_, err = file.Write(plainText)
	if err != nil {
		log.Fatalf("Error writing file: %v", err)
	}
}

func decryptFile2() {
	// Reading ciphertext file
	//C:\\Users\\Public\\Downloads\\ENC.bin" /path will be used for later
	file, err := os.Open("2ENC.bin")
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	cipherText, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Creating key
	key := []byte("xL3gGa4RM$S@LsSY")

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating cipher block: %v", err)
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM: %v", err)
	}

	// Deattached nonce and decrypt
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("Error decrypting file: %v", err)
	}

	// Writing decryption content
	f, err := os.Create("plaintext.txt")
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer f.Close()

	for i, b := range plainText {
		if i > 0 {
			f.WriteString(", ")
		}
		fmt.Fprintf(f, "0x%02x", b)
	}

}

// this function will split into a new line after 16bytes
func decryptFile3() {
	// Reading ciphertext file
	//C:\\Users\\Public\\Downloads\\ENC.bin" /path will be used for later
	file, err := os.Open("2ENC.bin")
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	cipherText, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Creating key
	key := []byte("xL3gGa4RM$S@LsSY")

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating cipher block: %v", err)
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM: %v", err)
	}

	// Deattached nonce and decrypt
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("Error decrypting file: %v", err)
	}

	// Writing decryption content
	f, err := os.Create("plaintext3.txt")
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer f.Close()

	counter := 0
	for i, b := range plainText {
		if i > 0 {
			f.WriteString(", ")
			counter++
		}
		if counter == 16 {
			f.WriteString("\n")
			counter = 0
		}
		fmt.Fprintf(f, "0x%02x", b)
	}
}


//This function will decrypt the 2ENC.bin file and write it to a global variable
func decryptFile4() {
	// Reading ciphertext file
	//C:\\Users\\Public\\Downloads\\ENC.bin" /path will be used for later
	file, err := os.Open("2ENC.bin")
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	cipherText, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Creating key
	key := []byte("xL3gGa4RM$S@LsSY")

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating cipher block: %v", err)
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM: %v", err)
	}

	// Deattached nonce and decrypt
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("Error decrypting file: %v", err)
	}

	// Assign the decryption content to the global variable
	shellcode = plainText

}