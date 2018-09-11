# gost
GOST in Go

GOST is a block algorithm from former Soviet Union. GOST is an acronim for 'Gosudarstvennyi Standard' (government standard).
It is a 64-bit block algorithm with 256-bit key. The algorithm iterates a simple encryption algorithm for 32 rounds.
If there is no better way to break GOST other than brute force, it is a very secure algoritm.
GOST is probably stronger than DES.
GOST's designers tried to achieve a balance between efficiency and security. They modified DES'a basic design to create an algorithm that is better suited for software implementation.

The code is not tuned for speed - main goal is explanation how works the algorithm.
As example program encrypt/decrypt only one block of data.

(All information from 'Applied Cryptography' of Burce Schneier)

# Example: How to test
```Go
package main

import (
	"fmt"
	"gost"
)

func main() {
	key := []byte{0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0}
	gost := gost.New(key)

	data := []uint32{0, 0}
	fmt.Printf("\nPlain text : 0x%x, 0x%x\n", data[0], data[1])
	gost.EncryptOneBlock(data)
	fmt.Printf("Cipher text: 0x%x, 0x%x\n", data[0], data[1])
	gost.DecryptOneBlock(data)
	fmt.Printf("Decryption : 0x%x, 0x%x\n\n", data[0], data[1])

	data = []uint32{1, 0}
	fmt.Printf("\nPlain text : 0x%x, 0x%x\n", data[0], data[1])
	gost.EncryptOneBlock(data)
	fmt.Printf("Cipher text: 0x%x, 0x%x\n", data[0], data[1])
	gost.DecryptOneBlock(data)
	fmt.Printf("Decryption : 0x%x, 0x%x\n\n", data[0], data[1])

	data = []uint32{0, 1}
	fmt.Printf("\nPlain text : 0x%x, 0x%x\n", data[0], data[1])
	gost.EncryptOneBlock(data)
	fmt.Printf("Cipher text: 0x%x, 0x%x\n", data[0], data[1])
	gost.DecryptOneBlock(data)
	fmt.Printf("Decryption : 0x%x, 0x%x\n\n", data[0], data[1])

	data = []uint32{4, 9}
	fmt.Printf("\nPlain text : 0x%x, 0x%x\n", data[0], data[1])
	gost.EncryptOneBlock(data)
	fmt.Printf("Cipher text: 0x%x, 0x%x\n", data[0], data[1])
	gost.DecryptOneBlock(data)
	fmt.Printf("Decryption : 0x%x, 0x%x\n\n", data[0], data[1])

	data = []uint32{0xffffffff, 0xffffffff}
	fmt.Printf("\nPlain text : 0x%x, 0x%x\n", data[0], data[1])
	gost.EncryptOneBlock(data)
	fmt.Printf("Cipher text: 0x%x, 0x%x\n", data[0], data[1])
	gost.DecryptOneBlock(data)
	fmt.Printf("Decryption : 0x%x, 0x%x\n\n", data[0], data[1])
}
```
