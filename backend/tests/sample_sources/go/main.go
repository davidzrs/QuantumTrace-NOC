// Source of personal-samples/binaries/legacy-agent: classical and post-quantum crypto linked
// into one executable, for the Go binary scanner (tests/test_binary_scanner.py). See
// ../README.md to rebuild. Never run, only compiled.
package main

import (
	"crypto"
	"crypto/des"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	digest := md5.Sum([]byte(os.Args[0]))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.MD5, digest[:])
	block, _ := des.NewTripleDESCipher(make([]byte, 24))
	dk, _ := mlkem.GenerateKey768()
	derived := pbkdf2.Key([]byte("password"), []byte("salt"), 4096, 32, sha256.New)
	fmt.Println(len(sig), block.BlockSize(), len(dk.EncapsulationKey().Bytes()), len(derived))
}
