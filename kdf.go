package main

import (
	"golang.org/x/crypto/argon2"
)

type (
	// KDF functions used to compute a key from a password and salt
	KDF func(password, salt []byte, keyLen uint32) []byte
)

func GetKDF(slow bool) KDF {
	if slow {
		return SlowKDF
	}
	return DefaultKDF
}

// DefaultKDF using Argon2.IDKey with time=10, memory=64*1024, threads=4
func DefaultKDF(password, salt []byte, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, 10, 64*1024, 4, keyLen)
}

// SlowKDF using Argon2.IDKey with time=1000, memory=512*1024, threads=4
func SlowKDF(password, salt []byte, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, 1000, 512*1024, 4, keyLen)
}
