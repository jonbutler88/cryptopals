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
		res[i] = input[i] ^ key[i % len(key)]
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
			res[c - 'a']++
			break
		case c >= 'A' && c <= 'Z':
			res[c - 'A']++
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
		panic("chiSquared calculated wrong count!")
	}

	for i := range expectedCharDistribution {
		expectedCount := expectedCharDistribution[i] * float64(len(input))
		observedCount := float64(observedCharCounts[i])

		x2 := math.Pow(observedCount - expectedCount, 2) / expectedCount

		if math.IsNaN(x2) {
			continue
		}

		sum += x2
	}

	return sum
}

func isAscii(input []byte) bool {
	for _, c := range input {
		if c >= 0x7f {
			return false
		}
	}
	return true
}

func isTopBitUniform(input []byte) bool {
	topBitVal := input[0] & 0x80
	for _, c := range input {
		if c & 0x80 != topBitVal {
			return false
		}
	}
	return true
}