package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func Generate(tokenSize uint) (string, error) {
	raw := make([]byte, tokenSize)

	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func Hash(token string) string {
	hash := sha256.Sum256([]byte(token))

	return base64.RawURLEncoding.EncodeToString(hash[:])
}
