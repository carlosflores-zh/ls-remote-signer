package cmd

import (
	"fmt"
	"github.com/lightsparkdev/go-sdk/objects"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// parseInvoice
var parseInvoice = &cobra.Command{
	Use:   "parse [entityID]",
	Short: "parse Invoice for receiving payment",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) < 1 {
			fmt.Printf("getEntity requires an entity ID")
			return
		}
		entityID := args[0]

		paymentRequestData, err := Client.DecodePaymentRequest(entityID)
		if err != nil {
			fmt.Printf("get entity failed: %v", err)
		}

		log.Printf("invoice data amount: %+v %s\n", (*paymentRequestData).(objects.InvoiceData).Amount.OriginalValue, (*paymentRequestData).(objects.InvoiceData).Amount.OriginalUnit.StringValue())

		fmt.Printf("PaymentRequestData: %+v\n", *paymentRequestData)
	},
}

func init() {
	rootCmd.AddCommand(parseInvoice)
}
