package jdc

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

func TestKeyDer(t *testing.T) {
	pass := "testpass"
	hashed := deriveKey(pass)

	if len(hashed) != 32 {
		t.Fail()
	}

	if fmt.Sprintf("%x", hashed) != "13d249f2cb4127b40cfa757866850278793f814ded3c587fe5889e889a7a9f6c" {
		t.Fail()
	}
}

func TestIVGen(t *testing.T) {
	rands := generateIV()
	if len(rands) != 32 {
		t.Fail()
	}
	fmt.Printf("%x\n", rands)
}

func TestPadding(t *testing.T) {
	iv := generateIV()

	data := []byte{}
	newData := padData(data, iv)
	if len(newData) != blockLen {
		t.Errorf("Incorrect padded length for no data")
	}

	data = make([]byte, 5)
	for i := 0; i < 5; i++ {
		data[i] = 5
	}
	newData = padData(data, iv)
	if len(newData) != 2*blockLen {
		t.Errorf("Incorrect padded length for 5 bytes data")
	}

	data = make([]byte, 32)
	for i := 0; i < 32; i++ {
		data[i] = 5
	}
	newData = padData(data, iv)
	if len(newData) != 2*blockLen {
		t.Errorf("Incorrect padded length for 32 bytes data")
	}

	data = append(data, 5)
	newData = padData(data, iv)
	if len(newData) != 3*blockLen {
		t.Errorf("Incorrect padded length for 33 bytes data")
	}
}

func TestEncryptDecryptBasic(t *testing.T) {
	input := []byte{5, 5, 5, 5}
	data := Encrypt(input, "hello")
	data = Decrypt(data, "hello")

	if !reflect.DeepEqual(data, input) {
		t.Fail()
	}

	input = make([]byte, 1e3)
	rand.Read(input)

	data = Encrypt(input, "password123")
	data = Decrypt(data, "password123")

	if !reflect.DeepEqual(data, input) {
		t.Fail()
	}
}

func TestLongEncryptDecrypt(t *testing.T) {
	data, _ := ioutil.ReadFile("test_input.txt")

	data = Encrypt(data, "password123")
	data = Decrypt(data, "password123")

	originalData, _ := ioutil.ReadFile("test_input.txt")
	if !reflect.DeepEqual(data, originalData) {
		t.Fail()
	}

	input := make([]byte, 1e6)
	rand.Read(input)

	data = Encrypt(input, "password123")
	data = Decrypt(data, "password123")

	if !reflect.DeepEqual(data, input) {
		t.Fail()
	}
}

func TestWrongKey(t *testing.T) {
	data, _ := ioutil.ReadFile("test_input.txt")

	data = Encrypt(data, "password123")
	data = Decrypt(data, "password")

	originalData, _ := ioutil.ReadFile("test_input.txt")
	if reflect.DeepEqual(data, originalData) {
		t.Errorf("Decryption with wrong key did not fail")
	}

	data, _ = ioutil.ReadFile("test_input.txt")
	data = Encrypt(data, "password123")
	data = Decrypt(data, "password1")

	if data != nil {
		t.Errorf("Decryption with wrong key did not fail correctly")
	}
}

// TODO benchmark for large amoutn of data encryption
func BenchmarkEncrypt(b *testing.B) {
	data := make([]byte, 1e7, 1e7) //10 mb of data for testing
	rand.Seed(time.Now().UnixNano())
	rand.Read(data)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Encrypt(data, "password")
	}
}

func BenchmarkDecrypt(b *testing.B) {
	data := make([]byte, 1e7, 1e7) //10 mb of data for testing
	rand.Seed(time.Now().UnixNano())
	rand.Read(data)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Decrypt(data, "password")
	}
}
