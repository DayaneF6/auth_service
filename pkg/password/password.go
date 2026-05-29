// Package password wraps bcrypt hashing and constant-time comparison.
package password

import "golang.org/x/crypto/bcrypt"

func Hash(plain string, cost int) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), cost)
	return string(b), err
}

func Compare(hash, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}
