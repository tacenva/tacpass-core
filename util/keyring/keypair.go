package keyring

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
)

var (
	kem  = hpke.DHKEM(ecdh.X25519())
	kdf  = hpke.HKDFSHA256()
	aead = hpke.ChaCha20Poly1305()
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := privateKey.Bytes()
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PublicKey:  base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateKeyBytes),
	}, nil
}

func FromKeys(publicKey, privateKey string) *KeyPair {
	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}
