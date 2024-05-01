package main

import (
	"fmt"
	"log"
	"os"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"

	kk "github.com/kriptakey/kk-go-sdk/kriptakey"
	kkreq "github.com/kriptakey/kk-go-sdk/kriptakey/request"
)

func main() {

	// Change these constants to the actual value in your environment
	DEMO_HOSTNAME := "target-kk-cs.com"
	DEMO_PORT := 8084

	DEMO_SLOT_ID := 1
	DEMO_SLOT_PASSWORD := "Password1!"

	DEMO_CLIENT_CERTIFICATE := "/PathToClient/Cert.pem"
	DEMO_CLIENT_PRIVATE_KEY := "/PathToClientKey/Priv.key"
	DEMO_CA_CERTIFICATE := "/PathToClient/Cert.pem"

	DEMO_KEY_ID := "AESEncryptionKey"

	connection, err := kk.InitializeConnection(DEMO_HOSTNAME, uint16(DEMO_PORT), DEMO_CLIENT_CERTIFICATE, DEMO_CLIENT_PRIVATE_KEY, DEMO_CA_CERTIFICATE)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	session, err := connection.Login(uint32(DEMO_SLOT_ID), DEMO_SLOT_PASSWORD)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- Session: ", protojson.Format(session))

	var encryptRequest kkreq.APIRequest_Encrypt
	var plaintexts []*kkreq.APIRequest_SingleEncrypt

	singleEncrypt := kkreq.APIRequest_SingleEncrypt{Plaintext: "Klavis", Aad: wrapperspb.String("aad1")}
	plaintexts = append(plaintexts, &singleEncrypt)

	encryptRequest.Plaintext = plaintexts

	encrypted, err := connection.EncryptAES(1, session.SessionToken, DEMO_KEY_ID, &encryptRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- EncryptAES: ", protojson.Format(encrypted))

	var decryptRequest kkreq.APIRequest_Decrypt
	var ciphertexts []*kkreq.APIRequest_SingleDecrypt

	for i, _ := range encrypted.Ciphertext {
		singleDecrypt := kkreq.APIRequest_SingleDecrypt{Ciphertext: encrypted.Ciphertext[i].Ciphertext, Iv: encrypted.Ciphertext[i].Iv, Mac: encrypted.Ciphertext[i].Mac, Aad: wrapperspb.String("aad1"), KeyID: DEMO_KEY_ID, KeyVersion: encrypted.KeyVersion}
		ciphertexts = append(ciphertexts, &singleDecrypt)
	}
	decryptRequest.Ciphertext = ciphertexts
	decrypted, err := connection.Decrypt(1, session.SessionToken, DEMO_KEY_ID, &decryptRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- DecryptAES: ", protojson.Format(decrypted))

}
