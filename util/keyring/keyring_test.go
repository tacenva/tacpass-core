package keyring

import "testing"

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	if len(keyPair.PublicKey) == 0 {
		t.Fatal("public key is empty")
	}

	if len(keyPair.PrivateKey) == 0 {
		t.Fatal("private key is empty")
	}

	t.Logf("public key size: %d bytes", len(keyPair.PublicKey))
	t.Logf("private key size: %d bytes", len(keyPair.PrivateKey))
}
