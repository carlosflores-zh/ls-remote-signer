package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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

		outgoingPayment, err := Client.PayInvoice(NodeId, invoice, 1000, 10000, nil)
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
