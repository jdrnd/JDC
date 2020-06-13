package jdc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
)

// Length of a block in bytes
const blockLen = 32

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
	randomBytes := make([]byte, blockLen)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return []byte{0}
	}
	return randomBytes
}

// TODO move to PKCS #7 standard as current method can lose trailing zeros in data
func padData(data []byte, iv []byte) []byte {
	var numBlocks int
	// Include extra block to store IV
	if len(data)%blockLen == 0 {
		numBlocks = (len(data) / blockLen) + 1
	} else {
		numBlocks = (len(data) / blockLen) + 2
	}

	newData := make([]byte, numBlocks*blockLen)
	for i := 0; i < blockLen; i++ {
		// copy in IV
		newData[i] = iv[i]
	}
	for i := 0; i < numBlocks*blockLen; i++ {
		if i < len(data) {
			newData[blockLen+i] = data[i]
		}
		// Otherwise data will be default 0 value
	}
	return newData
}

// Encrypt a buffer of data with MDC
func Encrypt(data []byte, password string) []byte {
	key := deriveKey(password)
	iv := generateIV()
	// padData places IV in first block of data
	data = padData(data, iv)

	numBlocks := (len(data) / blockLen) - 1 // Do not count IV as a block

	var crcSum uint32 = crc32.ChecksumIEEE(data)

	for i := 1; i <= numBlocks; i++ {
		feedback := deriveFeedback(key, data[blockLen*(i-1):blockLen*i])

		for j := 0; j < blockLen; j++ {
			data[blockLen*i+j] ^= feedback[j]
		}
	}
	data = append(data, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(data[len(data)-4:], crcSum)

	return data
}

// Decrypt a buffer of MDC-encrypted data
func Decrypt(data []byte, password string) []byte {
	key := deriveKey(password)
	numBlocks := ((len(data) - 4) / blockLen) - 1

	crcSum := binary.LittleEndian.Uint32(data[len(data)-4:])
	data = data[:len(data)-4]

	for i := numBlocks; i > 0; i-- {
		feedback := deriveFeedback(key, data[blockLen*(i-1):blockLen*i])

		for j := 0; j < blockLen; j++ {
			data[blockLen*i+j] ^= feedback[j]
		}
	}

	numTrailingZeros := 0
	for data[len(data)-1-numTrailingZeros] == 0 {
		numTrailingZeros++
	}
	decryptedCRC := crc32.ChecksumIEEE(data)

	if crcSum == decryptedCRC {
		return data[blockLen : len(data)-numTrailingZeros]
	}
	return nil
}
