package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/lightsparkdev/go-sdk/objects"
	"github.com/lightsparkdev/go-sdk/services"
	lightspark_crypto "github.com/lightsparkdev/lightspark-crypto-uniffi/lightspark-crypto-go"
	log "github.com/sirupsen/logrus"
)

var (
	NodeId    string
	Network   objects.BitcoinNetwork
	Client    *services.LightsparkClient
	Seed      []byte
	SeedRevoc []byte
	Account   *objects.Account
)

func Init() {
	var err error
	// MODIFY THOSE VARIABLES BEFORE RUNNING THE EXAMPLE
	apiClientID := os.Getenv("LS_CLIENT_ID")
	apiToken := os.Getenv("LS_TOKEN")
	baseUrl := os.Getenv("LS_BASE_URL")
	NodeId = os.Getenv("LS_NODE_ID")
	// hardcode network to mainnet for now
	Network = objects.BitcoinNetworkRegtest

	mnemonicSlice := strings.Split(os.Getenv("WORDS"), " ")
	Seed, err = lightspark_crypto.MnemonicToSeed(mnemonicSlice)
	if err != nil {
		log.Fatalf("mnemonic to seed failed: %v", err)
		return
	}

	mnemonicSliceRevoc := strings.Split(os.Getenv("WORDS_REVOC"), " ")
	SeedRevoc, err = lightspark_crypto.MnemonicToSeed(mnemonicSliceRevoc)
	if err != nil {
		log.Fatalf("mnemonic to seed failed: %v", err)
		return
	}

	//privateKey, err := crypto.GenerateKey()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//privateKeyBytes := crypto.FromECDSA(privateKey)
	//fmt.Println(hexutil.Encode(privateKeyBytes)[2:]) // fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19

	privString := "c03796ef32f0de7a30e8bf4f5eee2202e448b55119dd89911e79456c6069af53"
	Seed, _ := hex.DecodeString(privString)

	privKey, err := crypto.HexToECDSA(privString)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello")
	hash := sha256.Sum256(msg)

	log.Println(hex.EncodeToString(hash[:]))

	pubkey := privKey.Public().(*ecdsa.PublicKey)
	pubKeyData := elliptic.Marshal(pubkey, pubkey.X, pubkey.Y)

	xsign, err := privKey.Sign(rand.Reader, hash[:], nil)
	log.Printf("sig2: %v %d\n", hex.EncodeToString(xsign), len(xsign))

	signature, err := crypto.Sign(hash[:], privKey)
	if err != nil {
		log.Fatal(err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])

	log.Printf("sig1: %v %d\n", hex.EncodeToString(signature), len(signature))

	bool5 := ecdsa.Verify(pubkey, hash[:], r, s)
	boolx := crypto.VerifySignature(pubKeyData, hash[:], signature[:len(signature)-1])
	bool4 := ecdsa.VerifyASN1(pubkey, hash[:], xsign)
	bool6 := crypto.VerifySignature(pubKeyData, hash[:], xsign)

	sig := struct {
		R, S *big.Int
	}{}
	_, err = asn1.Unmarshal(xsign, &sig)
	if err != nil {
		log.Println("err:", err)
	}
	bool7 := ecdsa.Verify(pubkey, hash[:], sig.R, sig.S)
	// TODO: falta ver como obtener el recovation id
	log.Println("bool7:", bool7)
	log.Println("bool4:", bool4)
	log.Println("bool5:", bool5)
	log.Println("bool1:", boolx)
	log.Println("bool6:", bool6)

	Client = services.NewLightsparkClient(apiClientID, apiToken, &baseUrl)

	Account, err = Client.GetCurrentAccount()
	if err != nil {
		log.Fatalf("get current account failed: %v", err)
		return
	}

	//nonce, err := lightspark_crypto.GeneratePreimageNonce(Seed)
	//if err != nil {
	//	return
	//}
	//
	//log.Printf("Nonce: %v\n", nonce)
	//// log size
	//log.Printf("Nonce size: %v\n", len(nonce))
	//base64 := base642.StdEncoding.EncodeToString(nonce)
	//log.Printf("Nonce base64: %v\n", base64)
	//
	//nonce2 := make([]byte, 32) //generate a random 32 byte key for AES-256
	//if _, err := rand.Read(nonce2); err != nil {
	//	return
	//}
	//
	//log.Printf("Nonce2: %v\n", nonce2)
	//// log size
	//log.Printf("Nonce2 size: %v\n", len(nonce2))
	//base64 = base642.StdEncoding.EncodeToString(nonce2)
	//log.Printf("Nonce2 base64: %v\n", base64)

	Client.LoadNodeSigningKey(NodeId, *services.NewSigningKeyLoaderFromSignerMasterSeed(Seed, Network))
}
