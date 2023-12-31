package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// createWalletCmd represents the createWallet command
var createWalletCmd = &cobra.Command{
	Use:   "createWallet",
	Short: "Create node wallet address (used for funding)",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		address, err := Client.CreateNodeWalletAddress(NodeId)
		if err != nil {
			log.Printf("get node wallet failed: %v", err)
			return
		}
		log.Printf("Node %s wallet address created: %v\n", NodeId, address)
	},
}

func init() {
	rootCmd.AddCommand(createWalletCmd)
}
