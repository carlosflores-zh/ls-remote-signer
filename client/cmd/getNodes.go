package cmd

import (
	"github.com/lightsparkdev/go-sdk/objects"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"strings"
)

// getNodesCmd represents the getNodes command
var getNodesCmd = &cobra.Command{
	Use:   "getNodes",
	Short: "Get all nodes for the account",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		networks := []objects.BitcoinNetwork{Network}
		nodes, err := Account.GetNodes(Client.Requester,
			nil, &networks, nil, nil)
		if err != nil {
			log.Printf("get nodes failed: %v", err)
			return
		}

		for _, node := range nodes.Entities {
			balances := node.GetBalances()
			if strings.Split(node.GetId(), ":")[1] == strings.Split(NodeId, ":")[1] {
				log.Println(">>>> This is the node you are using:")
			}
			log.Printf("node_id: %s \n", node.GetId())
			log.Println("network:", node.GetBitcoinNetwork())
			log.Println("pubkey:", *(node.GetPublicKey()))
			log.Println("status:", node.GetStatus().StringValue())
			log.Println("createdAt:", node.GetCreatedAt())
			log.Printf("AvailableToSendBalance: %v %v \n", balances.AvailableToSendBalance.OriginalValue, balances.AvailableToSendBalance.OriginalUnit.StringValue())
			log.Printf("OwnedBalance: %v %v \n", balances.OwnedBalance.OriginalValue, balances.OwnedBalance.OriginalUnit.StringValue())
			log.Printf("AvailableToWithdrawBalance: %v %v \n \n \n", balances.AvailableToWithdrawBalance.OriginalValue, balances.AvailableToWithdrawBalance.OriginalUnit.StringValue())
		}

	},
}

func init() {
	rootCmd.AddCommand(getNodesCmd)
}
