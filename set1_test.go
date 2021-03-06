package cryptopals

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"os"
	"testing"
)

func Test1(t *testing.T) {
	input := []byte{
		0x49, 0x27, 0x6d, 0x20, 0x6b, 0x69, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x62, 0x72,
		0x61, 0x69, 0x6e, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x61, 0x20, 0x70, 0x6f, 0x69, 0x73, 0x6f, 0x6e, 0x6f, 0x75,
		0x73, 0x20, 0x6d, 0x75, 0x73, 0x68, 0x72, 0x6f, 0x6f, 0x6d}

	output := hex2base64(input)

	if bytes.Compare(output, []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")) != 0 {
		t.Errorf("Test failed, got: %s", output)
	}
}

func Test2(t *testing.T) {
	input := []byte{0x1c, 0x01, 0x11, 0x00, 0x1f, 0x01, 0x01, 0x00, 0x06, 0x1a, 0x02, 0x4b, 0x53, 0x53, 0x50, 0x09, 0x18, 0x1c}
	key := []byte{0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x75, 0x6c, 0x6c, 0x27, 0x73, 0x20, 0x65, 0x79, 0x65}

	output := fixedXor(input, key)

	if bytes.Compare(output, []byte{0x74, 0x68, 0x65, 0x20, 0x6b, 0x69, 0x64, 0x20, 0x64, 0x6f, 0x6e, 0x27, 0x74, 0x20, 0x70, 0x6c, 0x61, 0x79}) != 0 {
		t.Errorf("Test failed, got: %s", hex.EncodeToString(output))
	}
}

func Test3(t *testing.T) {
	input := []byte{0x1b, 0x37, 0x37, 0x33, 0x31, 0x36, 0x3f, 0x78, 0x15, 0x1b, 0x7f, 0x2b, 0x78, 0x34, 0x31, 0x33, 0x3d, 0x78, 0x39, 0x78,
		0x28, 0x37, 0x2d, 0x36, 0x3c, 0x78, 0x37, 0x3e, 0x78, 0x3a, 0x39, 0x3b, 0x37, 0x36}

	candidateAnswer, _ := breakSingleCharXor(input)

	if string(candidateAnswer) != "Cooking MC's like a pound of bacon" {
		t.Errorf("Test failed, got %s", string(candidateAnswer))
	}
}

func Test4(t *testing.T) {
	file, err := os.Open("data/4.txt")
	if err != nil {
		t.Errorf("Failed to open data/4.txt!")
	}
	defer file.Close()

	var lowestChiSquared float64 = 100
	var candidateAnswer []byte

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		candidate, err := hex.DecodeString(scanner.Text())
		if err != nil {
			t.Errorf("Failed to convert '%s' to hex string!", scanner.Text())
		}

		// Optimisation - I don't actually know how the non-plaintext values are generated, but I'm guessing they will
		// be random. As we can assume the plaintext is ascii and XOR'ed with a fixed repeating value, the top bit of
		// each byte of the ciphertext should be the same for each byte of ciphertext, and not the same in a random
		// value.
		if !isTopBitUniform(candidate) {
			continue
		}

		// TODO - refactor this to reuse code from challenge 3
		for i := 1; i < 255; i++ {
			try := fixedXor(candidate, []byte{byte(i)})

			// Optimisation - we assume plaintext is ascii, throw away anything outside that
			if !isAscii(try) {
				continue
			}

			// Optimisation - we only consider alphanumerics when calculating chi-squared. Some punctuation in a plaintext
			// is expected, but if more than 90% of try is non-alpha, skip it
			_, ignored := charCounts(try)
			if float64(ignored) > float64(len(try))*float64(0.1) {
				//fmt.Printf("Skipping due to %d ignored chars (threshold %f)\n", ignored, float64(len(try)) * float64(0.1))
				continue
			}

			tryChiSquared := chiSquared(try)

			if tryChiSquared < lowestChiSquared {
				lowestChiSquared = tryChiSquared
				candidateAnswer = try
			}
		}
	}

	if string(candidateAnswer) != "Now that the party is jumping\n" {
		t.Errorf("Test failed, got '%s'", string(candidateAnswer))
	}
}

func Test5(t *testing.T) {
	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")

	output := fixedXor(input, key)

	if bytes.Compare(output, []byte{0x0b, 0x36, 0x37, 0x27, 0x2a, 0x2b, 0x2e, 0x63, 0x62, 0x2c, 0x2e, 0x69, 0x69, 0x2a,
		0x23, 0x69, 0x3a, 0x2a, 0x3c, 0x63, 0x24, 0x20, 0x2d, 0x62, 0x3d, 0x63, 0x34, 0x3c, 0x2a, 0x26, 0x22, 0x63, 0x24,
		0x27, 0x27, 0x65, 0x27, 0x2a, 0x28, 0x2b, 0x2f, 0x20, 0x43, 0x0a, 0x65, 0x2e, 0x2c, 0x65, 0x2a, 0x31, 0x24, 0x33,
		0x3a, 0x65, 0x3e, 0x2b, 0x20, 0x27, 0x63, 0x0c, 0x69, 0x2b, 0x20, 0x28, 0x31, 0x65, 0x28, 0x63, 0x26, 0x30, 0x2e,
		0x27, 0x28, 0x2f}) != 0 {
		t.Errorf("Test failed, got: %s", hex.EncodeToString(output))
	}
}

func Test6(t *testing.T) {
	ciphertext, err := readBase64File("data/6.txt")
	if err != nil {
		t.Errorf("Error reading input")
	}

	// Find the key size. Split the ciphertext into blocks of key size and calculate the hamming distance between them
	keySize := 0
	smallestNormalisedDistance := 1000.0
	for ks := 2; ks < 40; ks++ {
		comparisons := 0.0
		blockDistances := 0.0
		curBlocks := ciphertext

		for len(curBlocks) > ks*2 {
			blockDistances += float64(hammingDistance(curBlocks[:ks], curBlocks[ks:ks*2]))
			curBlocks = curBlocks[ks:]
			comparisons++
		}

		normalisedDistance := (blockDistances / comparisons) / float64(ks)

		//fmt.Printf("The hamming distance for key size %d is %f\n", ks, normalisedDistance)

		if normalisedDistance < smallestNormalisedDistance {
			smallestNormalisedDistance = normalisedDistance
			keySize = ks
		}
	}

	//fmt.Printf("The likely key size is %d\n", keySize)

	// Transpose the blocks based on the key size
	blocks := make([][]byte, keySize)
	for i := 0; i < len(ciphertext); i += keySize {
		for j := 0; j < keySize; j++ {

			// I think it's fine for the ciphertext length not to be a multiple of the key size
			if i+j < len(ciphertext) {
				blocks[j] = append(blocks[j], ciphertext[i+j])
			}
		}
	}

	var recoveredKey []byte
	for i := range blocks {
		_, key := breakSingleCharXor(blocks[i])
		recoveredKey = append(recoveredKey, key)
	}

	//fmt.Printf("The recovered key is: %s\n", recoveredKey)

	// Now, decrypt the ciphertext
	//fmt.Println(string(fixedXor(ciphertext, recoveredKey)))

	if bytes.Compare(recoveredKey, []byte("Terminator X: Bring the noise")) != 0 {
		t.Errorf("Test failed, got: %s", string(recoveredKey))
	}
}

func Test7(t *testing.T) {
	ciphertext, err := readBase64File("data/7.txt")
	if err != nil {
		t.Errorf("Error reading input")
	}

	result := make([]byte, len(ciphertext))

	key := []byte("YELLOW SUBMARINE")
	block, _ := aes.NewCipher(key)

	for i := 0; i < len(ciphertext); i += len(key) {
		block.Decrypt(result[i:i+len(key)], ciphertext[i:i+len(key)])
	}

	if bytes.Compare(result[0:33], []byte("I'm back and I'm ringin' the bell")) != 0 {
		t.Errorf("Test failed, got: %s", string(result[0:33]))
	}
}

func Test8(t *testing.T) {
	file, err := os.Open("data/8.txt")
	if err != nil {
		t.Errorf("Failed to open data/4.txt!")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		candidate, err := hex.DecodeString(scanner.Text())
		if err != nil {
			t.Errorf("Failed to convert '%s' to hex string!", scanner.Text())
		}

		for i := 0; i < len(candidate); i += 16 {
			block := candidate[i : i+16]
			for j := 0; j < len(candidate); j += 16 {
				// Skip comparing with ourselves
				if i == j {
					continue
				}

				if bytes.Compare(block, candidate[j:j+16]) == 0 {
					//fmt.Println("Detected ECB mode!")
					return
				}
			}
		}
	}

	t.Errorf("Did not detect ECB mode :(")
}
