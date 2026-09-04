package keyring

import (
	"bytes"
	"testing"
)

func TestSealAndOpen(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	plaintext := []byte("tacenva vault key")

	wrappedKey, err := keyPair.Seal(plaintext)
	if err != nil {
		t.Fatalf("failed to seal data: %v", err)
	}

	if wrappedKey == "" {
		t.Fatal("wrapped key is empty")
	}

	decrypted, err := keyPair.Open(wrappedKey)
	if err != nil {
		t.Fatalf("failed to open data: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf(
			"decrypted data mismatch: got %q, want %q",
			decrypted,
			plaintext,
		)
	}
}

func TestSealProducesDifferentCiphertext(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	plaintext := []byte("tacenva vault key")

	first, err := keyPair.Seal(plaintext)
	if err != nil {
		t.Fatalf("failed to seal first data: %v", err)
	}

	second, err := keyPair.Seal(plaintext)
	if err != nil {
		t.Fatalf("failed to seal second data: %v", err)
	}

	if first == second {
		t.Fatal("sealing the same data produced identical ciphertext")
	}
}

func TestOpenWithWrongKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	otherKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate second key pair: %v", err)
	}

	plaintext := []byte("tacenva vault key")

	wrappedKey, err := keyPair.Seal(plaintext)
	if err != nil {
		t.Fatalf("failed to seal data: %v", err)
	}

	_, err = otherKeyPair.Open(wrappedKey)
	if err == nil {
		t.Fatal("expected opening with wrong key pair to fail")
	}
}
