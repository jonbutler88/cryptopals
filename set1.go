package cryptopals

import (
	"bytes"
	"encoding/base64"
	"math"
)

func hex2base64(input []byte) []byte {
	out := bytes.NewBuffer([]byte{})
	enc := base64.NewEncoder(base64.StdEncoding, out)
	enc.Write(input)
	return out.Bytes()
}

func fixedXor(input []byte, key []byte) []byte {
	res := make([]byte, len(input))

	for i := range input {
		res[i] = input[i] ^ key[i%len(key)]
	}

	return res
}

func charCounts(input []byte) ([]int, int) {
	res := make([]int, 27)
	ignored := 0

	for _, c := range input {
		// We handle 3 cases, space, capital and lowercase letter
		switch {
		case c == ' ':
			res[26]++
			break
		case c >= 'a' && c <= 'z':
			res[c-'a']++
			break
		case c >= 'A' && c <= 'Z':
			res[c-'A']++
			break
		default:
			ignored++
		}
	}

	return res, ignored
}

func chiSquared(input []byte) float64 {
	var sum float64

	observedCharCounts, _ := charCounts(input)

	if len(expectedCharDistribution) != len(observedCharCounts) {
		panic("chiSquared distribution is the wrong length!")
	}

	for i := range expectedCharDistribution {
		expectedCount := expectedCharDistribution[i] * float64(len(input))
		observedCount := float64(observedCharCounts[i])

		x2 := math.Pow(observedCount-expectedCount, 2) / expectedCount

		if math.IsNaN(x2) {
			continue
		}

		sum += x2
	}

	return sum
}

func isAscii(input []byte) bool {
	for _, c := range input {
		if c > 0x7f {
			return false
		}
	}
	return true
}

func isTopBitUniform(input []byte) bool {
	topBitVal := input[0] & 0x80
	for _, c := range input {
		if c&0x80 != topBitVal {
			return false
		}
	}
	return true
}

func breakSingleCharXor(input []byte) ([]byte, byte) {
	var lowestChiSquared float64 = 100
	var candidateAnswer []byte
	var candidateKey byte

	for i := 1; i < 255; i++ {
		try := fixedXor(input, []byte{byte(i)})

		// Optimisation - we assume plaintext is ascii, throw away anything outside that
		if !isAscii(try) {
			//fmt.Println("Discarding non-ascii try")
			continue
		}

		// Optimisation - we only consider alphanumerics when calculating chi-squared. Some punctuation in a plaintext
		// is expected, but if more than 85% of try is non-alpha, skip it
		_, ignored := charCounts(try)
		if float64(ignored) > float64(len(try))*float64(0.15) {
			//fmt.Printf("Skipping due to %d ignored chars (threshold %f)\n", ignored, float64(len(try)) * float64(0.1))
			continue
		}

		tryChiSquared := chiSquared(try)

		if tryChiSquared < lowestChiSquared {
			lowestChiSquared = tryChiSquared
			candidateAnswer = try
			candidateKey = byte(i)
		}
	}

	return candidateAnswer, candidateKey
}

func hammingDistance(input1, input2 []byte) int {
	if len(input1) != len(input2) {
		panic("hammingDistance called with 2 slices of different lengths!")
	}

	distance := 0

	for i := range input1 {
		var j, mask byte
		for j = 0; j < 8; j++ {
			mask = 1 << j

			if input1[i]&mask != input2[i]&mask {
				distance += 1
			}
		}

	}

	return distance
}
