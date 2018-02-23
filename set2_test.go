package cryptopals

import (
	"bytes"
	"testing"
)

func Test9(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	paddedInput := pkcs7Pad(input, 20)
	if bytes.Compare(paddedInput, []byte("YELLOW SUBMARINE\x04\x04\x04\x04")) != 0 {
		t.Errorf("Test failed, got: %s", string(paddedInput))
	}
}

func Test10(t *testing.T) {
	ciphertext, err := readBase64File("data/10.txt")
	if err != nil {
		t.Error(err)
	}

	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	plaintext := cbcDecrypt(ciphertext, key, iv)

	if bytes.Compare(plaintext[0:33], []byte("I'm back and I'm ringin' the bell")) != 0 {
		t.Errorf("Test failed, got: %s", string(plaintext[0:33]))
	}
}
