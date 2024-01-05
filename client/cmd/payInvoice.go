package cmd

import (
	lightspark_crypto "github.com/lightsparkdev/lightspark-crypto-uniffi/lightspark-crypto-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

// payInvoiceCmd represents the payInvoice command
var payInvoiceCmd = &cobra.Command{
	Use:   "payInvoice",
	Short: "Create a test mode invoice and pay it",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Printf("Please provide an invoice")
			return
		}

		defaultAmount := int64(0)

		invoice := args[0]

		if invoice == "test" {
			invoiceTest, err := Client.CreateTestModeInvoice(NodeId, int64(10000000), nil, nil)
			if err != nil {
				log.Printf("create lightning invoice failed: %v", err)
				return
			}

			log.Printf("Invoice created: %v\n", invoiceTest)
			invoice = *invoiceTest
		}

		lnFees, err := Client.GetLightningFeeEstimateForInvoice(NodeId, invoice, &defaultAmount)
		if err != nil {
			log.Printf("get node wallet failed: %v", err)
			return
		}

		log.Printf("Fee estimate: %v\n", lnFees.FeeEstimate.OriginalValue)
		log.Println(NodeId)

		mnemonicSlice := strings.Split(os.Getenv("WORDS"), " ")

		log.Printf("Mnemonic: %v\n", mnemonicSlice)
		Seed, err = lightspark_crypto.MnemonicToSeed(mnemonicSlice)
		if err != nil {
			log.Fatalf("mnemonic to seed failed: %v", err)
			return
		}

		outgoingPayment, err := Client.PayInvoice(NodeId, invoice, 1000, lnFees.FeeEstimate.OriginalValue, nil)
		if err != nil {
			log.Printf("pay invoice failed: %v", err)
			return
		}

		log.Printf("Invoice paid with payment id: %v\n", outgoingPayment.Id)
	},
}

func init() {
	rootCmd.AddCommand(payInvoiceCmd)
}
