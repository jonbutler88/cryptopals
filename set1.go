package cryptopals

import (
	"bytes"
	"encoding/base64"
	"sort"
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

func charDistribution(input []byte) []float64 {
	res := make([]float64, len(input))

	for _, c := range input {
		// We handle 3 cases, space, capital and lowercase letter
		switch {
		case c == ' ':
			res[26] += 1 / float64(len(input))
			break
		case c >= 'a' && c <= 'z':
			res[c - 'a'] += 1 / float64(len(input))
			break
		case c >= 'A' && c <= 'Z':
			res[c - 'A'] += 1 / float64(len(input))
			break
		}
	}

	return res
}

func sortedByteDistribution(input []byte) []float64 {
	res := make([]float64, 256)

	for _, c := range input {
		res[c] += 1 / float64(len(input))
	}

	sort.Sort(sort.Reverse(sort.Float64Slice(res)))

	return res
}