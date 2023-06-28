package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

const oaepLabel = "Location-UC"

func ExportRsaPrivateKeyAsPemStr(privateKey *rsa.PrivateKey) string {
	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateBytes,
		},
	)
	return string(privatePem)
}

func ParseRsaPrivateKeyFromPem(privatePem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privatePem)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ExportRsaPublicKeyAsPemStr(publicKey *rsa.PublicKey) (string, error) {
	publicBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	publicPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicBytes,
		},
	)

	return string(publicPem), nil
}

func ParseRsaPublicKeyFromPem(pubPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("key type is not RSA")
	}
}

func RsaOaepEncrypt(secretMessage []byte, key rsa.PublicKey) []byte {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key, secretMessage, []byte(oaepLabel))
	HandleError(err)
	return ciphertext
}

func RsaOaepDecrypt(cipherText []byte, privateKey rsa.PrivateKey) []byte {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &privateKey, cipherText, []byte(oaepLabel))
	HandleError(err)
	if debug {
		println("Decrypted plaintext:", string(plaintext))
	}
	return plaintext
}

func HandleError(e error) {
	if e != nil {
		panic(e)
	}
}

func AesEncrypt(text []byte, key []byte) ([]byte, error) {
	if debug {
		println("INFO: Starting AES Encryption")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// creates a new byte array the size of the ClientNonce
	// which must be passed to Seal
	nonce, err := RandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	encryptedOutput := gcm.Seal(nonce, nonce, text, nil)

	return encryptedOutput, nil
}

func AesDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if debug {
		println("DEBUG: Starting AES Decryption")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("len(ciphertext) < nonceSize")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if debug {
		println("DEBUG: Plaintext is:", string(plaintext))
	}
	return plaintext, nil
}

func RandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
