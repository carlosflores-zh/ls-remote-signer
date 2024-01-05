package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// fundCmd represents the fundNode command
// ONLY FOR TESTNET
var fundCmd = &cobra.Command{
	Use:   "fund",
	Short: "Execute fundNode operation, to fund a node with 10,000,000 sats in testnet",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("Funding node: %v\n", NodeId)

		depositAmount, err := Client.FundNode(NodeId, 200000) // 10,000,000 sats
		if err != nil {
			log.Printf("fund node failed: %v", err)
			return
		}

		log.Printf("Amount funded: %v %v \n", depositAmount.OriginalValue, depositAmount.OriginalUnit.StringValue())
	},
}

func init() {
	rootCmd.AddCommand(fundCmd)
}
