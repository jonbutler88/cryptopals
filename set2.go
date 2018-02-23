package cryptopals

import (
	"crypto/aes"
)

func pkcs7Pad(input []byte, blockSize int) []byte {
	result := input
	paddingSize := blockSize % len(input)

	for i := 0; i < paddingSize; i++ {
		result = append(result, byte(paddingSize))
	}

	return result
}

func cbcDecrypt(ciphertext []byte, key []byte, iv []byte) []byte {
	plaintext := make([]byte, 0, len(ciphertext))

	block, _ := aes.NewCipher(key)
	currentXor := iv
	currentBlock := make([]byte, block.BlockSize())

	for i := 0; i < len(ciphertext); i += block.BlockSize() {
		block.Decrypt(currentBlock, ciphertext[i:i+block.BlockSize()])
		plaintext = append(plaintext, fixedXor(currentBlock, currentXor)...)

		// Update the XOR
		currentXor = ciphertext[i : i+block.BlockSize()]
	}

	return plaintext
}
