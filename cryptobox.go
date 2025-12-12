package cryptobox

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/nacl/box"
)

type CryptoBox struct{}

// ----------- Helper functions ----------
func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func b64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// ----------- Exported functions ----------

// encryptNext
func (n *CryptoBox) EncryptNext(payload, clientPrivB64, serverPubB64, nonceB64 string) (string, error) {
	clientPriv, err := b64Decode(clientPrivB64)
	if err != nil {
		return "", err
	}
	serverPub, err := b64Decode(serverPubB64)
	if err != nil {
		return "", err
	}
	nonceBytes, err := b64Decode(nonceB64)
	if err != nil {
		return "", err
	}
	if len(clientPriv) != 32 || len(serverPub) != 32 || len(nonceBytes) != 24 {
		return "", fmt.Errorf("invalid key sizes")
	}

	var clientPrivKey [32]byte
	copy(clientPrivKey[:], clientPriv)
	var serverPubKey [32]byte
	copy(serverPubKey[:], serverPub)
	var nonce [24]byte
	copy(nonce[:], nonceBytes)

	sharedKey := new([32]byte)
	box.Precompute(sharedKey, &serverPubKey, &clientPrivKey)

	encrypted := box.SealAfterPrecomputation(nil, []byte(payload), &nonce, sharedKey)

	return b64Encode(encrypted), nil
}

// decryptNext
func (n *CryptoBox) DecryptNext(cipherB64, clientPrivB64, serverPubB64, nonceB64 string) (string, error) {
	clientPriv, err := b64Decode(clientPrivB64)
	if err != nil {
		return "", err
	}
	serverPub, err := b64Decode(serverPubB64)
	if err != nil {
		return "", err
	}
	nonceBytes, err := b64Decode(nonceB64)
	if err != nil {
		return "", err
	}
	if len(clientPriv) != 32 || len(serverPub) != 32 || len(nonceBytes) != 24 {
		return "", fmt.Errorf("invalid key sizes")
	}

	var clientPrivKey [32]byte
	copy(clientPrivKey[:], clientPriv)
	var serverPubKey [32]byte
	copy(serverPubKey[:], serverPub)
	var nonce [24]byte
	copy(nonce[:], nonceBytes)

	sharedKey := new([32]byte)
	box.Precompute(sharedKey, &serverPubKey, &clientPrivKey)

	ciphertext, err := b64Decode(cipherB64)
	if err != nil {
		return "", err
	}

	decrypted, ok := box.OpenAfterPrecomputation(nil, ciphertext, &nonce, sharedKey)
	if !ok {
		return "", fmt.Errorf("decryption failed")
	}

	return string(decrypted), nil
}

func (n *CryptoBox) EcdsaSign(message, privateKey string) (string, error) {

	privateKeyBytes := []byte(privateKey)

	privBlock, _ := pem.Decode(privateKeyBytes)
	if privBlock == nil {
		return "", errors.New("❌ Failed to decode PEM block for private key")
	}

	privKey, err := x509.ParseECPrivateKey(privBlock.Bytes)
	if err != nil {
		return "", errors.New("❌ Failed to parse EC private key: " + err.Error())
	}

	hash := sha256.Sum256([]byte(message))
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, hash[:])
	sig, _ := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	sigBase64 := base64.StdEncoding.EncodeToString(sig)

	return sigBase64, nil
}
