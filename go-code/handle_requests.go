package main

import (
	"bytes"
	"capnproto.org/go/capnp/v3"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// MAC for pings on CLIENT
var shaHmac hash.Hash

func handleRequests() {
	go func() {
		// Listen to incoming UDP packets
		udpConnection, err := net.ListenPacket("udp", ":"+strings.Split(publicEndpoint, ":")[1])
		HandleError(err)
		defer func(udpServer net.PacketConn) {
			HandleError(udpServer.Close())
		}(udpConnection)

		buf := make([]byte, 80)
		for {
			n, addr, err := udpConnection.ReadFrom(buf)
			if err != nil {
				continue
			}
			processPing(udpConnection, addr, buf[:n])
		}
	}()

	// Client Endpoints
	http.HandleFunc("/init-attestation", initAttestation)
	// Server Endpoints
	http.HandleFunc("/debug-timestamp", sendSignedTimestamp)
	http.HandleFunc("/init-timestamp-attestation", initTimestampAttestation)
	log.Fatal(http.ListenAndServe(":"+strings.Split(publicEndpoint, ":")[1], nil))
}

func initAttestation(w http.ResponseWriter, r *http.Request) {
	println("INFO: Endpoint Hit: Initialising attestation")

	requestBody, err := io.ReadAll(r.Body)
	HandleError(err)
	var attestationRequest AttestationRequest
	HandleError(json.Unmarshal(requestBody, &attestationRequest))
	if attestationRequest.Repetitions > (1<<15 - 1) {
		_, err := fmt.Fprintf(os.Stderr, "ERROR: Max. value for repetitions is %d!\n", 1<<15-1)
		HandleError(err)
		return
	}
	targetPublicKey, err := ParseRsaPublicKeyFromPem(attestationRequest.TargetPublicKeyPem)
	HandleError(err)

	aesKey, err := RandomBytes(32)
	HandleError(err)

	// Initialize HMAC for ping/pong messages
	shaHmac = hmac.New(sha256.New, aesKey)

	// Encrypting Client's random AES Session Key encrypted via server's public key
	aesKeyEncrypted := RsaOaepEncrypt(aesKey, *targetPublicKey)

	// Generation and encryption of timestampRequest
	nonce, err := RandomBytes(16)
	HandleError(err)
	timestampRequest := TimestampRequest{
		Repetitions:       attestationRequest.Repetitions,
		ClientNonce:       nonce,
		ClientUdpEndpoint: publicEndpoint,
	}
	timestampRequestJson, err := json.Marshal(timestampRequest)
	HandleError(err)
	encryptedTsRequestJson, err := AesEncrypt(timestampRequestJson, aesKey)
	HandleError(err)
	if debug {
		println("DEBUG: encryptedTsRequestJson:")
		println(encryptedTsRequestJson)
	}

	timestampRequestMessage := TimestampRequestMessage{
		ClientsEncryptedAesSessionKey:    aesKeyEncrypted,
		ClientsEncryptedTimestampRequest: encryptedTsRequestJson,
	}

	if debug {
		println("DEBUG: timestampRequestJson is:")
		fmt.Println(timestampRequestJson)
	}

	// Marshalling timestamp request message with encrypted contents
	timestampRequestMessageJson, err := json.Marshal(timestampRequestMessage)
	println("INFO: Sending TimestampRequest")
	//goland:noinspection HttpUrlsUsage
	timestampResponseMessage, err := http.Post(
		"http://"+attestationRequest.TargetEndpoint+"/init-timestamp-attestation",
		"application/json",
		bytes.NewBuffer(timestampRequestMessageJson),
	)
	if err != nil {
		log.Fatal(err)
	}
	encryptedResponse, err := io.ReadAll(timestampResponseMessage.Body)
	HandleError(err)
	HandleError(timestampResponseMessage.Body.Close())
	timestampResponseBytes, err := AesDecrypt(encryptedResponse, aesKey)
	HandleError(err)

	// Pass-through JSON result
	_, err = w.Write(timestampResponseBytes)
	HandleError(err)

	// Output result to console
	var timestampResponse TimestampResponse
	HandleError(json.Unmarshal(timestampResponseBytes, &timestampResponse))
	println("Timestamp-Response:", timestampResponse.ServerSignedTimestamp.TimeValue)
	println("Timestamp-Delay:", timestampResponse.MeasuredDelay)
}

func processPing(udpConnection net.PacketConn, addr net.Addr, buffer []byte) {
	if debug {
		fmt.Printf("DEBUG: Received Ping Message (%d bytes)\n", len(buffer))
		fmt.Println(buffer)
	}

	pingBytes := buffer[:len(buffer)-sha256.Size]
	timestampMessage, err := capnp.Unmarshal(pingBytes)
	HandleError(err)
	pingMac := buffer[len(buffer)-sha256.Size:]
	shaHmac.Reset()
	shaHmac.Write(pingBytes)
	pingSum := shaHmac.Sum(nil)
	if !hmac.Equal(pingMac, pingSum) {
		_, err = fmt.Fprintln(os.Stderr, "Timestamp ping message has been corrupted, ignore message...")
		return
	}
	pingPong, err := ReadRootTimestampMessage(timestampMessage)
	HandleError(err)

	// Decrement repetition field
	pingPong.SetRepetition(pingPong.Repetition() + 1<<15)

	pongBytes, err := timestampMessage.Marshal()
	HandleError(err)
	shaHmac.Reset()
	shaHmac.Write(pongBytes)
	pongMac := shaHmac.Sum(nil)
	// Reset buffer and fill with message and MAC
	buffer = append(buffer[:0], pongBytes...)
	buffer = append(buffer, pongMac...)

	_, err = udpConnection.WriteTo(buffer, addr)
	HandleError(err)
}

func sendSignedTimestamp(w http.ResponseWriter, _ *http.Request) {
	println("INFO: Endpoint Hit: Send signedTimestamp")
	HandleError(json.NewEncoder(w).Encode(signedTimestamp))
}

func initTimestampAttestation(w http.ResponseWriter, r *http.Request) {
	println("INFO: Endpoint Hit: initTimestampAttestation")
	l := log.New(os.Stdout, "[AAA] ", log.Ldate|log.Ltime)
	l.Printf("")

	reqBody, err := io.ReadAll(r.Body)
	HandleError(err)
	var timestampRequestMsg TimestampRequestMessage
	err = json.Unmarshal(reqBody, &timestampRequestMsg)
	HandleError(err)
	if debug {
		println("DEBUG: Unmarshalling complete, received JSON object:")
		fmt.Printf("%+v\n", timestampRequestMsg)
		println("INFO: Decrypting AES session key")
	}

	// receiving client's AES session key
	sessionKey := RsaOaepDecrypt(timestampRequestMsg.ClientsEncryptedAesSessionKey, *privateKey)

	HandleError(err)
	if debug {
		fmt.Printf("DEBUG:\tBase64 decoded:\n")
		fmt.Println(reqBody)
		fmt.Printf("DEBUG:\tReceived encrypted Request:\n")
		fmt.Println(timestampRequestMsg.ClientsEncryptedTimestampRequest)
	}

	bodyDecrypted, err := AesDecrypt(timestampRequestMsg.ClientsEncryptedTimestampRequest, sessionKey)
	HandleError(err)

	var timestampRequest TimestampRequest
	HandleError(json.Unmarshal(bodyDecrypted, &timestampRequest))

	if debug {
		fmt.Printf(
			"DEBUG: Received TimestampRequest. Repetitions: %d ClientNonce: %d\n",
			timestampRequest.Repetitions,
			timestampRequest.ClientNonce,
		)
	}

	timestampSignedTemp, _ := createTimestampWithSignature(timestampRequest.ClientNonce)
	timestampResponse := TimestampResponse{
		ServerPublicKey:       publicKey,
		ClientNonce:           timestampRequest.ClientNonce,
		ServerSignedTimestamp: timestampSignedTemp,
		MeasuredDelay:         math.MaxUint,
	}

	if timestampRequest.Repetitions > 0 {
		timestampResponse.MeasuredDelay = measureDelays(timestampRequest, sessionKey)
	}

	timestampResponseJson, err := json.Marshal(timestampResponse)
	HandleError(err)
	timestampResponseEncrypted, err := AesEncrypt(timestampResponseJson, sessionKey)
	HandleError(err)
	println("INFO: Sending TimestampResponse")
	_, err = w.Write(timestampResponseEncrypted)
	HandleError(err)
}

func measureDelays(timestampRequest TimestampRequest, sessionKey []byte) uint {
	if debug {
		println("DEBUG: Starting PingPong Sequence with the following session key:")
		fmt.Println(sessionKey)
	}

	// Buffers
	writeBuffer := make([]byte, 80)
	readBuffer := make([]byte, 80)

	// Open UDP "connection"
	udpServer, err := net.ResolveUDPAddr("udp", timestampRequest.ClientUdpEndpoint)
	HandleError(err)
	conn, err := net.DialUDP("udp", nil, udpServer)
	HandleError(err)
	defer func(conn *net.UDPConn) {
		HandleError(conn.Close())
	}(conn)

	starts := make([]time.Time, timestampRequest.Repetitions)
	// Asynchronously send pings
	go func() {
		// MAC for pings
		shaHmac := hmac.New(sha256.New, sessionKey)

		// Allocate and initialize Cap'n Proto fields
		arena := capnp.SingleSegment(nil)
		timestampMessage, timestampSegment, err := capnp.NewMessage(arena)
		HandleError(err)
		ping, err := NewRootTimestampMessage(timestampSegment)
		HandleError(err)
		HandleError(ping.SetNonce(timestampRequest.ClientNonce))
		println("n repetitions:", timestampRequest.Repetitions)
		repetition := uint16(0)
		for repetition < timestampRequest.Repetitions {
			ping.SetRepetition(repetition)
			pingBytes, err := timestampMessage.Marshal()
			if debug {
				println("DEBUG: Send repetition", ping.Repetition())
			}
			HandleError(err)
			shaHmac.Reset()
			shaHmac.Write(pingBytes)
			pingMac := shaHmac.Sum(nil)
			// Reset writeBuffer and fill with message and MAC
			writeBuffer = append(writeBuffer[:0], pingBytes...)
			writeBuffer = append(writeBuffer, pingMac...)

			starts[repetition] = time.Now()
			// Write writeBuffer
			_, err = conn.Write(writeBuffer)
			HandleError(err)
			if debug {
				fmt.Printf("DEBUG: Sent Ping Message with MAC (%d bytes)\n", len(writeBuffer))
				fmt.Println(writeBuffer)
			}

			// Sleep 1µs (for some reason, this seems to be an ideal value for localhost tests)
			time.Sleep(1 * time.Microsecond)

			repetition++
		}
	}()

	measuredDelay := uint(math.MaxUint)
	for {
		// MAC for pings
		shaHmac := hmac.New(sha256.New, sessionKey)

		// Set a read deadline
		err := conn.SetReadDeadline(time.Now().Add(time.Second))
		HandleError(err)
		// Read result to readBuffer
		bytesRead, err := conn.Read(readBuffer)
		// Return on timeout
		if err != nil {
			if err.(net.Error).Timeout() {
				fmt.Printf("INFO: MeasuredDelayResult %d\n", measuredDelay)
				return measuredDelay
			} else {
				HandleError(err)
			}
		}
		// Note arrival time of packet
		arrival := time.Now()
		if debug {
			fmt.Printf("DEBUG: Received Pong Message (%d bytes)\n", bytesRead)
			fmt.Println(readBuffer[:bytesRead])
		}

		// Process response
		pongBytes := readBuffer[:bytesRead-sha256.Size]
		pongTimestampMessage, err := capnp.Unmarshal(pongBytes)
		HandleError(err)
		pongMac := readBuffer[bytesRead-sha256.Size : bytesRead]
		pong, err := ReadRootTimestampMessage(pongTimestampMessage)
		HandleError(err)
		// Validate MAC
		shaHmac.Reset()
		shaHmac.Write(pongBytes)
		if !hmac.Equal(pongMac, shaHmac.Sum(nil)) {
			_, _ = fmt.Fprintln(os.Stderr, "WARN: Pong with invalid MAC received, ignoring.")
			continue
		}
		// Validate nonce
		pongNonce, err := pong.Nonce()
		HandleError(err)
		if bytes.Compare(timestampRequest.ClientNonce, pongNonce) != 0 {
			_, _ = fmt.Fprintln(os.Stderr, "WARN: Pong with invalid nonce received, ignoring.")
			continue
		}

		repetition := pong.Repetition() - 1<<15
		secs := uint(arrival.Sub(starts[repetition]).Microseconds())
		if debug {
			fmt.Printf("DEBUG: MeasuredDelayCycle %d\n", secs)
		}
		// Set measuredDelay to the lowest delay observed
		if secs < measuredDelay {
			measuredDelay = secs
		}
	}
}
