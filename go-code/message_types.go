package main

import "crypto/rsa"

type AttestationRequest struct {
	Repetitions        uint16
	TargetEndpoint     string
	TargetPublicKeyPem []byte
}

type SignedTimestamp struct {
	TimeValue      string
	ClientNonce    int
	SignatureValue []byte
}

type TimestampRequest struct {
	Repetitions       uint16
	ClientNonce       []byte
	ClientUdpEndpoint string
}

type TimestampRequestMessage struct {
	ClientsEncryptedAesSessionKey    []byte
	ClientsEncryptedTimestampRequest []byte
}

type TimestampResponse struct {
	ServerPublicKey       *rsa.PublicKey
	ServerSignedTimestamp SignedTimestamp
	ClientNonce           []byte
	MeasuredDelay         uint
}
