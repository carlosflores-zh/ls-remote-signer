package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/lightsparkdev/go-sdk/objects"
	log "github.com/sirupsen/logrus"

	lightspark_crypto "github.com/lightsparkdev/lightspark-crypto-uniffi/lightspark-crypto-go"
)

type Config struct {
	ApiEndpoint     *string
	ApiClientId     string
	ApiClientSecret string
	WebhookSecret   string
	MasterSeed      []byte
	RevocationSeed  []byte
}

func NewConfigFromEnv() (*Config, error) {
	mnemonic := strings.Split(os.Getenv("WORDS"), " ")
	mnemonicRevocation := strings.Split(os.Getenv("WORDS_REVOC"), " ")

	masterSeed, err := lightspark_crypto.MnemonicToSeed(mnemonic)
	if err != nil {
		log.Fatalf("Invalid mnemonic: %s", err)
	}

	revocationSeed, err := lightspark_crypto.MnemonicToSeed(mnemonicRevocation)
	if err != nil {
		log.Fatalf("Invalid mnemonic: %s", err)
	}

	// hardcode network to regtest
	network := objects.BitcoinNetworkRegtest

	apiClientId := os.Getenv("LS_CLIENT_ID")
	apiClientSecret := os.Getenv("LS_TOKEN")
	webhookSecret := os.Getenv("LS_WEBHOOK_SECRET")
	apiEndpointStr := os.Getenv("LS_BASE_URL")

	log.Print("Loaded configuration:")
	log.Printf("  - API_CLIENT_ID: %s", showEmpty(apiClientId))
	log.Printf("  - API_CLIENT_SECRET: %s", showEmpty(fmt.Sprint(len(apiClientSecret))))
	log.Printf("  - WEBHOOK_SECRET: %s", showEmpty(fmt.Sprint(len(webhookSecret))))
	log.Printf("  - MASTER_SEED: %s", showEmpty(fmt.Sprint(len(masterSeed))))
	log.Printf("  - MASTER_SEED Revocation: %s", showEmpty(fmt.Sprint(len(revocationSeed))))
	log.Printf("  - API_ENDPOINT: %s", showEmpty(apiEndpointStr))
	log.Printf("  - NETWORK: %s", network.StringValue())

	return &Config{
		ApiEndpoint:     &apiEndpointStr,
		ApiClientId:     apiClientId,
		ApiClientSecret: apiClientSecret,
		WebhookSecret:   webhookSecret,
		MasterSeed:      masterSeed,
		RevocationSeed:  revocationSeed,
	}, nil
}

func showEmpty(str string) string {
	if str == "" {
		return "<empty>"
	}

	return str
}
