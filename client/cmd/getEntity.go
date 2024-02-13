package cmd

import (
	"fmt"
	"github.com/lightsparkdev/go-sdk/objects"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// getEntityCmd represents the getEntity command
var getEntityCmd = &cobra.Command{
	Use:   "getEntity [entityID]",
	Short: "Get entity by ID, right now OutgoingPayment is the only supported entity type",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Printf("getEntity requires an entity ID")
			return
		}

		entityID := args[0]

		entity, err := Client.GetEntity(entityID)
		if err != nil {
			fmt.Printf("get entity failed: %v", err)
		}

		if (*entity).GetTypename() == "OutgoingPayment" {
			outgoingPayment := (*entity).(objects.OutgoingPayment)
			log.Printf("%s > %s > %s \n", outgoingPayment.GetTypename(), outgoingPayment.GetId(), outgoingPayment.GetStatus().StringValue())
			log.Printf("OutgoingPayment struct: %+v\n", outgoingPayment)
			if outgoingPayment.FailureMessage != nil {
				log.Printf("FailureMessage: %+v\n", outgoingPayment.FailureMessage)
			}
		} else if (*entity).GetTypename() == "WithdrawalRequest" {
			withdrawalRequest := (*entity).(objects.WithdrawalRequest)
			log.Printf("%s > %s > %s \n", withdrawalRequest.GetTypename(), withdrawalRequest.GetId(), withdrawalRequest.Status.StringValue())
			log.Printf("IncomingPayment struct: %+v\n", withdrawalRequest)
		} else {
			fmt.Printf("entity: %+v\n", *entity)
		}
	},
}

func init() {
	rootCmd.AddCommand(getEntityCmd)
}
