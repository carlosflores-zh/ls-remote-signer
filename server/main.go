// Copyright ©, 2023-present, Lightspark Group, Inc. - All Rights Reserved
package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/lightsparkdev/go-sdk/objects"
	"github.com/lightsparkdev/go-sdk/services"
	"github.com/lightsparkdev/go-sdk/webhooks"

	"github.com/carlosflores-zh/remote-signing-poc/config"
	"github.com/lightsparkdev/go-sdk/remotesigning"
)

func main() {
	conf, err := config.NewConfigFromEnv()
	if err != nil {
		log.Fatalf("Invalid conf: %s", err)
	}

	lsClient := services.NewLightsparkClient(conf.ApiClientId, conf.ApiClientSecret, conf.ApiEndpoint)

	engine := gin.Default()

	// default ping
	engine.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "hello\n")
	})

	engine.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	engine.POST("/ln/webhooks", func(c *gin.Context) {
		signature := c.Request.Header.Get(webhooks.SIGNATURE_HEADER)
		if signature == "" {
			log.Print("ERROR: Signature was not present")
		}

		data, err := c.GetRawData()
		if err != nil {
			log.Printf("ERROR: Couldn't get data: %s", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		event, err := webhooks.VerifyAndParse(data, signature, conf.WebhookSecret)
		if err != nil {
			log.WithFields(log.Fields{"data": string(data)}).Printf("ERROR: Couldn't parse webhook data: %s", err)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		logf := log.WithFields(log.Fields{"eventID": event.EventId, "eventType": event.EventType})
		logf.Printf("Received webhook data: %s", string(data))

		switch event.EventType {
		case objects.WebhookEventTypeRemoteSigning:
			resp, err := remotesigning.HandleRemoteSigningWebhook(
				lsClient, remotesigning.PositiveValidator{}, *event, conf.MasterSeed)
			if err != nil {
				logf.Printf("ERROR: Unable to handle remote signing webhook: %s", err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			if resp != "" {
				logf.Printf("Webhook complete with response: %s", resp)
			}

			c.Status(http.StatusNoContent)
		case objects.WebhookEventTypeWithdrawalFinished:
			fetchEntity(lsClient, event.EntityId)
			c.Status(http.StatusNoContent)

		case objects.WebhookEventTypeLowBalance:
			fetchEntity(lsClient, event.EntityId)
			c.Status(http.StatusNoContent)

		default:
			c.Status(http.StatusNoContent)
		}
	})

	engine.Run(":8000")
}

func fetchEntity(lsClient *services.LightsparkClient, entityID string) {
	entity, err := lsClient.GetEntity(entityID)
	if err != nil {
		fmt.Printf("get entity failed: %v", err)
	}

	if entity == nil {
		fmt.Printf("entity not found")
	}

	entityX := *entity

	wr, ok := entityX.(objects.WithdrawalRequest)
	if ok {
		log.Printf("---- id:%s status  %+v", wr.Id, wr.Status.StringValue())
	} else {

		fmt.Printf("\n We fetched entity: %+v\n", *entity)

	}
}
