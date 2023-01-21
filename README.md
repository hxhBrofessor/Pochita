# Pochita

![files](./Images/pochita.jpg)

I was motivated to create this project after completing Sektor7's Malware Essentials course. Despite the abundance of proofs-of-concept for C, there needed to be more readily understandable and easy-to-follow examples for Golang. This project aims to fill that gap by clearly demonstrating the encryption and shellcode execution process, as guided by Sektor7's course. It's important to note that this code is purely for demonstration purposes and is not intended to bypass anti-virus or endpoint detection and response software.

Shoutout to my good friends [v4quero](https://github.com/v4quero) & @JMFL for their constant support and encouragement to never settle for complacency.

## The Method to the Madness


### 1. Generating Shellcode

On your Linux terminal run the following command:

```
msfvenom -p windows/x64/exec CMD=calc -f raw > calc.bin
```

***Note:*** I compiled and moved the shellcode to the windows host to run `testing-encryptor.go` script to generate the encrypted binary.


### 2. Encryption

Navigate to the `Encryption` folder and execute the following in your terminal `go run testing-encryptor.go `

The code will have you point to the designated bin file you wish to encrypt and what you would like to name the
newly encrypt file.

```azure
Enter the name of the binary to encrypt:
C:\Users\test\Documents\calc.bin
Name your encrypted binary(EX:ENC2.bin):
ENC3.bin
```
***Note:*** Make sure to change the encrytion 

### 3. Modify `shellcode-execute` file

- Make sure to change the URL in the getFile()

- and replace `2ENC.bin` with your encrypted binary that you generated