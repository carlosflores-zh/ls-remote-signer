/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// getTxsCmd represents the getTxs command
var getTxsCmd = &cobra.Command{
	Use:   "getTxs",
	Short: "A brief description of your command",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

		var count int64 = 50
		transactionsConnection, err := Account.GetTransactions(
			Client.Requester,
			&count,   // first
			nil,      // after
			nil,      // types
			nil,      // after_date
			nil,      // before_date
			&Network, // bitcoin_network
			nil,      // lightning_node_id
			nil,      // statuses
			nil,      // exclude_failures
		)
		if err != nil {
			log.Printf("get transactions failed: %v", err)
			return
		}
		log.Printf("You have %v transactions in total.\n", transactionsConnection.Count)

		var transactionId string
		for _, transaction := range transactionsConnection.Entities {
			transactionId = transaction.GetId()
			log.Printf(
				"    - %v at %v: %v %v (%v)\n",
				transactionId,
				transaction.GetCreatedAt(),
				transaction.GetAmount().OriginalValue,
				transaction.GetAmount().OriginalUnit.StringValue(),
				transaction.GetStatus().StringValue(),
			)
		}
	},
}

func init() {
	rootCmd.AddCommand(getTxsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getTxsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getTxsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}