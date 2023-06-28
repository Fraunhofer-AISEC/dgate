package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"time"
)

var publicKey *rsa.PublicKey
var privateKey *rsa.PrivateKey
var signedTimestamp SignedTimestamp
var debug = false
var publicEndpoint string

func main() {
	var keyPath string
	// Obtain CLI parameters via flag package
	flag.BoolVar(&debug, "v", false, "Show debug output")
	flag.StringVar(&publicEndpoint, "p", "localhost:10000",
		"Public UDP endpoint for remote requests AND local server ports")
	flag.StringVar(&keyPath, "k", "rsa_key.pem", "Path to PEM file with private key of this node.")
	flag.Parse()

	// For fresh creation of keys chose [true]
	if _, err := os.Stat(keyPath); err != nil {
		var err error
		println("Create new keypair due to some issue with the given key path", keyPath)
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
		HandleError(err)
		privateKeyPem := ExportRsaPrivateKeyAsPemStr(privateKey)
		HandleError(os.WriteFile(keyPath, []byte(privateKeyPem), 0644))
		fmt.Printf("Successfully wrote RSA key to \"%s\".\n", keyPath)
		publicKeyPem, err := ExportRsaPublicKeyAsPemStr(&privateKey.PublicKey)
		HandleError(err)
		println("Corresponding public key PEM:")
		println(publicKeyPem)
	} else {
		// Statically stored keys given here:
		privateKeyPem, err := os.ReadFile(keyPath)
		HandleError(err)
		fmt.Printf("Successfully read RSA key from \"%s\".\n", keyPath)

		// Import private key from PEM
		privateKey, err = ParseRsaPrivateKeyFromPem(privateKeyPem)
		HandleError(err)
		publicKey := privateKey.PublicKey
		publicKeyPem, err := ExportRsaPublicKeyAsPemStr(&publicKey)
		HandleError(err)

		println("The following public key (PEM output) is used:")
		println(publicKeyPem)
	}

	println("Ready!")
	handleRequests()
}

func createTimestampWithSignature(nonce []byte) (SignedTimestamp, error) {
	println("INFO: Creating timestamp with signature")
	t := time.Now().UTC()
	if debug {
		println(t.Format("20060102150405"))
	}
	message := []byte(t.Format("20060102150405") + "_nonce:" + string(nonce))
	hashed := sha256.Sum256(message)

	rng := rand.Reader
	signature, err := rsa.SignPKCS1v15(rng, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		_, err := fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		if err != nil {
			panic(err)
		}
		return SignedTimestamp{}, err
	}

	signedTimestampLocal := SignedTimestamp{
		TimeValue:      t.Format("20060102150405"),
		SignatureValue: signature,
	}
	return signedTimestampLocal, nil
}
