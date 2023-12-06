package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// getChannelsCmd represents the getChannels command
var getChannelsCmd = &cobra.Command{
	Use:   "getChannels",
	Short: "Get all channels of the account",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		countc := int64(200)
		channels, err := Account.GetChannels(Client.Requester, Network, nil, nil, nil, &countc)
		if err != nil {
			log.Printf("get channels failed: %v", err)
			return
		}

		log.Printf("You have %v channels in total.\n", len(channels.Entities))

		for _, channel := range channels.Entities {
			log.Printf("ChannelID: %+v Status:%s LocalBalance:%d %s \n", channel.Id, channel.Status.StringValue(), (*(channel.LocalBalance)).OriginalValue, (*(channel.LocalBalance)).OriginalUnit.StringValue())
		}
	},
}

func init() {
	rootCmd.AddCommand(getChannelsCmd)
}
