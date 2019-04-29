package JDC

import (
	"crypto/rand"
	"crypto/sha256"
)

const BLOCK_LEN = 32

func deriveKey(password string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hashed := hasher.Sum(nil)
	return hashed
}

// Given the hashed key and previous cyphertext block return the hash of them concatenated together
func deriveFeedback(key []byte, prev []byte) []byte {
	hasher := sha256.New()
	hasher.Write(key)
	hasher.Write(prev)
	hashed := hasher.Sum(nil)

	return hashed
}

func generateIV() []byte {
	randomBytes := make([]byte, BLOCK_LEN)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return []byte{0}
	}
	return randomBytes
}

func padData(data []byte, iv []byte) []byte {
	// Include extra block to store IV
	numBlocks := (len(data) / BLOCK_LEN) + 2

	newData := make([]byte, numBlocks*BLOCK_LEN)
	for i:=0; i<BLOCK_LEN; i++ {
		// copy in IV
		newData[i] = iv[i]
	}
	for i:=0; i< numBlocks*BLOCK_LEN; i++ {
		if i<len(data) {
			newData[BLOCK_LEN+i] = data[i]
		}
		// Otherwise data will be default 0 value
	}
	return newData
}

func Encrypt(data []byte, password string) []byte {
	key := deriveKey(password)
	iv := generateIV()
	// padData places IV in first block of data
	data = padData(data, iv)

	numBlocks := (len(data) / BLOCK_LEN) - 1 // Do not count IV as a block

	for i:=1; i<= numBlocks; i++ {
		feedback := deriveFeedback(key, data[BLOCK_LEN*(i-1):BLOCK_LEN*i])

		for j:=0; j<BLOCK_LEN; j++ {
			data[BLOCK_LEN*i + j] ^= feedback[j]
		}
	}
	return data
}

func Decrypt(data []byte, password string) []byte {
	key := deriveKey(password)
	numBlocks := (len(data) / BLOCK_LEN) - 1

	for i:= numBlocks; i>0; i-- {
		feedback := deriveFeedback(key, data[BLOCK_LEN*(i-1):BLOCK_LEN*i])

		for j:=0; j<BLOCK_LEN; j++ {
			data[BLOCK_LEN*i + j] ^= feedback[j]
		}
	}

	numTrailingZeros := 0
	for data[len(data) - 1-numTrailingZeros] == 0 {
		numTrailingZeros++
	}
	return data[BLOCK_LEN:len(data)-numTrailingZeros]
}

