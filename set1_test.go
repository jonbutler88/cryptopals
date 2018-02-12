package cryptopals

import (
	"testing"
	"bytes"
	"encoding/hex"
	"os"
	"bufio"
)

func Test1_1(t *testing.T) {
	input := []byte{
		0x49, 0x27, 0x6d, 0x20, 0x6b, 0x69, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x62, 0x72,
		0x61, 0x69, 0x6e, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x61, 0x20, 0x70, 0x6f, 0x69, 0x73, 0x6f, 0x6e, 0x6f, 0x75,
		0x73, 0x20, 0x6d, 0x75, 0x73, 0x68,	0x72, 0x6f, 0x6f, 0x6d}

	output := hex2base64(input)

	if bytes.Compare(output, []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")) != 0 {
		t.Errorf("Test failed, got: %s", output)
	}
}

func Test1_2(t *testing.T) {
	input := []byte{0x1c,0x01,0x11,0x00,0x1f,0x01,0x01,0x00,0x06,0x1a,0x02,0x4b,0x53,0x53,0x50,0x09,0x18,0x1c}
	key := []byte{0x68,0x69,0x74,0x20,0x74,0x68,0x65,0x20,0x62,0x75,0x6c,0x6c,0x27,0x73,0x20,0x65,0x79,0x65}

	output := fixedXor(input, key)

	if bytes.Compare(output, []byte{0x74,0x68,0x65,0x20,0x6b,0x69,0x64,0x20,0x64,0x6f,0x6e,0x27,0x74,0x20,0x70,0x6c,0x61,0x79}) != 0 {
		t.Errorf("Test failed, got: %s", hex.EncodeToString(output))
	}
}

func Test1_3(t *testing.T) {
	input := []byte{0x1b,0x37,0x37,0x33,0x31,0x36,0x3f,0x78,0x15,0x1b,0x7f,0x2b,0x78,0x34,0x31,0x33,0x3d,0x78,0x39,0x78,
		0x28,0x37,0x2d,0x36,0x3c,0x78,0x37,0x3e,0x78,0x3a,0x39,0x3b,0x37,0x36}

	var lowestChiSquared float64 = 100
	var candidateAnswer []byte

	for i := 1; i < 255; i++ {
		try := fixedXor(input, []byte{byte(i)})

		// Optimisation - we assume plaintext is ascii, throw away anything outside that
		if !isAscii(try) {
			continue
		}

		// Optimisation - we only consider alphanumerics when calculating chi-squared. Some punctuation in a plaintext
		// is expected, but if more than 90% of try is non-alpha, skip it
		_, ignored := charCounts(try)
		if float64(ignored) > float64(len(try)) * float64(0.1) {
			//fmt.Printf("Skipping due to %d ignored chars (threshold %f)\n", ignored, float64(len(try)) * float64(0.1))
			continue
		}

		tryChiSquared := chiSquared(try)

		if tryChiSquared < lowestChiSquared {
			lowestChiSquared = tryChiSquared
			candidateAnswer = try
		}
	}

	if string(candidateAnswer) != "Cooking MC's like a pound of bacon" {
		t.Errorf("Test failed, got %s", string(candidateAnswer))
	}
}

func Test1_4(t *testing.T) {
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

		for i := 1; i < 255; i++ {
			try := fixedXor(candidate, []byte{byte(i)})

			// Optimisation - we assume plaintext is ascii, throw away anything outside that
			if !isAscii(try) {
				continue
			}

			// Optimisation - we only consider alphanumerics when calculating chi-squared. Some punctuation in a plaintext
			// is expected, but if more than 90% of try is non-alpha, skip it
			_, ignored := charCounts(try)
			if float64(ignored) > float64(len(try)) * float64(0.1) {
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

func Test1_5(t *testing.T) {
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

func Test1_6(t *testing.T) {
	file, err := os.Open("data/6.txt")
	if err != nil {
		t.Errorf("Failed to open data/6.txt!")
	}
	defer file.Close()
}