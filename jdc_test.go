package JDC

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"
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

	data := []byte{5,5,5,5,5,5}
	newData := padData(data, iv)
	if len(newData) != BLOCK_LEN { t.Fail() }

	data = []byte{5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5}
	newData = padData(data, iv)
	if len(newData) != 2*BLOCK_LEN { t.Fail() }

	data = []byte{5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5}
	newData = padData(data, iv)
	if len(newData) != 2*BLOCK_LEN { t.Fail() }
}

func TestEncryptDecryptBasic(t *testing.T) {
	input := []byte{5,5,5,5}
	data := Encrypt(input, "hello")
	fmt.Println(data)
	data = Decrypt(data, "hello")
	fmt.Println(data)

	if !reflect.DeepEqual(data,input) {
		t.Fail()
	}
}

func TestLongEncryptDecrypt(t *testing.T) {
	data,_ := ioutil.ReadFile("test_input.txt")

	data = Encrypt(data, "password123")
	data = Decrypt(data, "password123")

	originalData, _ := ioutil.ReadFile("test_input.txt")
	if !reflect.DeepEqual(data, originalData) {
		t.Fail()
	}
}

func TestWrongKey(t *testing.T) {
	data,_ := ioutil.ReadFile("test_input.txt")

	data = Encrypt(data, "password123")
	data = Decrypt(data, "password")

	originalData, _ := ioutil.ReadFile("test_input.txt")
	if reflect.DeepEqual(data, originalData) {
		t.Fail()
	}
}