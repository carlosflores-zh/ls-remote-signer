// Copyright ©, 2023-present, Lightspark Group, Inc. - All Rights Reserved
package remotesigning

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"

	"github.com/lightsparkdev/go-sdk/crypto"
	lightspark_crypto "github.com/lightsparkdev/lightspark-crypto-uniffi/lightspark-crypto-go"

	"github.com/lightsparkdev/go-sdk/objects"
	"github.com/lightsparkdev/go-sdk/scripts"
	"github.com/lightsparkdev/go-sdk/services"
	"github.com/lightsparkdev/go-sdk/webhooks"
)

// HandleRemoteSigningWebhook handles a webhook event that is related to remote signing.
//
// This method should only be called with a webhook event that has the event_type `WebhookEventTypeRemoteSigning`.
// The method will call the appropriate handler for the sub_event_type of the webhook.
//
// Args:
//
//		client: The LightsparkClient used to respond to webhook events.
//	    validator: A validator for deciding whether to sign events.
//		webhook: The webhook event that you want to handle.
//		seedBytes: The bytes of the master seed that you want to use to sign messages or derive keys.
func HandleRemoteSigningWebhook(
	client *services.LightsparkClient,
	validator Validator,
	event webhooks.WebhookEvent,
	seedBytes []byte,
) (string, error) {
	logf := log.WithFields(log.Fields{"eventID": event.EventId, "eventType": event.EventType})

	if event.EventType != objects.WebhookEventTypeRemoteSigning {
		return "", errors.New("event event is not for remote signing")
	}

	if event.Data == nil {
		return "", errors.New("event data is missing")
	}

	var subtype objects.RemoteSigningSubEventType
	subEventTypeStr := (*event.Data)["sub_event_type"].(string)
	logf.Printf("Received remote signing event with sub_event_type %s", subEventTypeStr)

	err := subtype.UnmarshalJSON([]byte(`"` + subEventTypeStr + `"`))
	if err != nil {
		return "", errors.New("invalid remote signing sub_event_type")
	}

	if !validator.ShouldSign(event) {
		return DeclineToSignMessages(client, event)
	}

	request, err := ParseRemoteSigningRequest(event)
	if err != nil {
		return "", err
	}

	response, err := HandleSigningRequest(request, seedBytes)
	if err != nil {
		// string, errx := DeclineToSignMessages(client, event)
		// if errx != nil {
		// 	log.Printf("Error, declining to sign messages: %s", errx)
		// }
		//
		// log.Printf("decline signing request: %s", string)
		logf.Printf("Error handling signing request: %s", err)
		return "", err
	}

	if response == nil {
		// No response is required for this event type.
		return "", nil
	}

	return HandleSigningResponse(client, response)
}

func HandleSigningRequest(request SigningRequest, seedBytes []byte) (SigningResponse, error) {
	var response SigningResponse
	var err error
	switch request.Type() {
	case objects.RemoteSigningSubEventTypeEcdh:
		response, err = HandleEcdhRequest(request.(*ECDHRequest), seedBytes)
	case objects.RemoteSigningSubEventTypeGetPerCommitmentPoint:
		response, err = HandleGetPerCommitmentPointRequest(request.(*GetPerCommitmentPointRequest), seedBytes)
	case objects.RemoteSigningSubEventTypeReleasePerCommitmentSecret:
		response, err = HandleReleasePerCommitmentSecretRequest(request.(*ReleasePerCommitmentSecretRequest), seedBytes)
	case objects.RemoteSigningSubEventTypeDeriveKeyAndSign:
		response, err = HandleDeriveKeyAndSignRequest(request.(*DeriveKeyAndSignRequest), seedBytes)
	case objects.RemoteSigningSubEventTypeRequestInvoicePaymentHash:
		// TODO: used to create an invoice, we may have to store this event in DB
		response, err = HandleInvoicePaymentHashRequest(request.(*InvoicePaymentHashRequest), seedBytes)
	case objects.RemoteSigningSubEventTypeSignInvoice:
		// TODO: haven't seen this event yet
		log.Printf("request received for sign Invoice: %+v", request.(*SignInvoiceRequest))
		response, err = HandleSignInvoiceRequest(request.(*SignInvoiceRequest), seedBytes)
	case objects.RemoteSigningSubEventTypeReleasePaymentPreimage:
		// TODO: to close the channel we have to release the preimage
		response, err = HandleReleaseInvoicePreimageRequest(request.(*ReleasePaymentPreimageRequest), seedBytes)
	case objects.RemoteSigningSubEventTypeRevealCounterpartyPerCommitmentSecret:
		// TODO: RevealCounterpartyPerCommitmentSecret, we have to store this event in DB
		// TODO: should we implement this tx logic, because there is no info about it in the sdk
		log.Printf("request received that we should store to sign justice: %+v", request.(*ReleaseCounterpartyPerCommitmentSecretRequest))
		return nil, nil
	default:
		return nil, errors.New("webhook event is not for remote signing")
	}

	if err != nil {
		return nil, err
	}

	return response, nil
}

func HandleSigningResponse(client *services.LightsparkClient, response SigningResponse) (string, error) {
	graphql := response.GraphqlResponse()

	result, err := client.Requester.ExecuteGraphql(graphql.Query, graphql.Variables, nil)
	if err != nil {
		log.Printf("Error executing graphql: %s", err)
		return "", err
	}

	output := result[graphql.OutputField].(map[string]interface{})
	var responseObj objects.UpdateNodeSharedSecretOutput
	outputJson, err := json.Marshal(output)
	if err != nil {
		return "", err
	}

	// This is just to validate the response.
	err = json.Unmarshal(outputJson, &responseObj)
	if err != nil {
		return "", err
	}

	return string(outputJson), nil
}

func DeclineToSignMessages(client *services.LightsparkClient, event webhooks.WebhookEvent) (string, error) {
	signingJobsJson := (*event.Data)["signing_jobs"]
	if signingJobsJson == nil {
		return "", errors.New("missing signing_jobs in webhook")
	}
	signingJobsJsonString, err := json.Marshal(signingJobsJson.([]interface{}))
	if err != nil {
		return "", err
	}

	var signingJobs []SigningJob
	err = json.Unmarshal(signingJobsJsonString, &signingJobs)
	if err != nil {
		return "", err
	}

	var payloadIds []string
	for _, signingJob := range signingJobs {
		payloadIds = append(payloadIds, signingJob.Id)
	}

	variables := map[string]interface{}{
		"payload_ids": payloadIds,
	}

	response, err := client.Requester.ExecuteGraphql(scripts.DECLINE_TO_SIGN_MESSAGES_MUTATION, variables, nil)
	if err != nil {
		return "", err
	}

	output := response["decline_to_sign_messages"].(map[string]interface{})
	var responseObj objects.DeclineToSignMessagesOutput
	outputJson, err := json.Marshal(output)
	if err != nil {
		return "", err
	}

	// This is just to validate the response.
	err = json.Unmarshal(outputJson, &responseObj)
	if err != nil {
		return "", err
	}

	return "rejected signing", nil
}

func HandleEcdhRequest(request *ECDHRequest, seedBytes []byte) (*ECDHResponse, error) {
	bitcoinNetwork, err := bitcoinNetworkConversion(request.BitcoinNetwork)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := crypto.ECDH(seedBytes, bitcoinNetwork, request.PeerPubKeyHex)
	if err != nil {
		return nil, err
	}

	response := ECDHResponse{
		NodeId:          request.NodeId,
		SharedSecretHex: sharedSecret,
	}

	return &response, nil
}

func HandleGetPerCommitmentPointRequest(request *GetPerCommitmentPointRequest, seedBytes []byte) (*GetPerCommitmentPointResponse, error) {
	bitcoinNetwork, err := bitcoinNetworkConversion(request.BitcoinNetwork)
	if err != nil {
		return nil, err
	}

	perCommitmentPoint, err := lightspark_crypto.GetPerCommitmentPoint(
		seedBytes,
		bitcoinNetwork,
		request.DerivationPath,
		request.PerCommitmentPointIdx)
	if err != nil {
		return nil, err
	}

	response := GetPerCommitmentPointResponse{
		ChannelId:             request.ChannelId,
		PerCommitmentPointIdx: request.PerCommitmentPointIdx,
		PerCommitmentPointHex: hex.EncodeToString(perCommitmentPoint),
	}

	return &response, nil
}

func HandleReleasePerCommitmentSecretRequest(request *ReleasePerCommitmentSecretRequest, seedBytes []byte) (*ReleasePerCommitmentSecretResponse, error) {
	bitcoinNetwork, err := bitcoinNetworkConversion(request.BitcoinNetwork)
	if err != nil {
		return nil, err
	}

	perCommitmentSecret, err := lightspark_crypto.ReleasePerCommitmentSecret(
		seedBytes,
		bitcoinNetwork,
		request.DerivationPath,
		request.PerCommitmentPointIdx)
	if err != nil {
		return nil, err
	}

	response := ReleasePerCommitmentSecretResponse{
		ChannelId:             request.ChannelId,
		PerCommitmentPointIdx: request.PerCommitmentPointIdx,
		PerCommitmentSecret:   hex.EncodeToString(perCommitmentSecret),
	}

	return &response, nil
}

func HandleInvoicePaymentHashRequest(request *InvoicePaymentHashRequest, seedBytes []byte) (*InvoicePaymentHashResponse, error) {
	nonce, err := lightspark_crypto.GeneratePreimageNonce(seedBytes)
	if err != nil {
		return nil, err
	}
	paymentHash, err := lightspark_crypto.GeneratePreimageHash(seedBytes, nonce)
	if err != nil {
		return nil, err
	}

	nonce_str := hex.EncodeToString(nonce)

	response := InvoicePaymentHashResponse{
		InvoiceId:      request.InvoiceId,
		PaymentHashHex: hex.EncodeToString(paymentHash),
		Nonce:          &nonce_str,
	}

	log.Printf("REQUEST_INVOICE_PAYMENT_HASH response %+v", response)

	return &response, nil
}

func HandleSignInvoiceRequest(request *SignInvoiceRequest, seedBytes []byte) (*SignInvoiceResponse, error) {
	bitcoinNetwork, err := bitcoinNetworkConversion(request.BitcoinNetwork)
	if err != nil {
		return nil, err
	}

	hash, err := hex.DecodeString(request.PaymentRequestHash)
	if err != nil {
		return nil, err
	}

	signedInvoice, err := lightspark_crypto.SignInvoiceHash(seedBytes, bitcoinNetwork, hash)
	if err != nil {
		log.Fatalf("Error signing invoice: %v", err)
		return nil, err
	}

	response := SignInvoiceResponse{
		InvoiceId:  request.InvoiceId,
		Signature:  hex.EncodeToString(signedInvoice.Signature),
		RecoveryId: signedInvoice.RecoveryId,
	}

	return &response, nil
}

func HandleReleaseInvoicePreimageRequest(request *ReleasePaymentPreimageRequest, seedBytes []byte) (*ReleasePaymentPreimageResponse, error) {
	nonce := request.Nonce
	if nonce == nil {
		return nil, errors.New("missing preimage_nonce in webhook")
	}
	nonceBytes, err := hex.DecodeString(*nonce)
	if err != nil {
		return nil, err
	}

	preimage, err := lightspark_crypto.GeneratePreimage(seedBytes, nonceBytes)
	if err != nil {
		return nil, err
	}

	response := ReleasePaymentPreimageResponse{
		InvoiceId:       request.InvoiceId,
		PaymentPreimage: hex.EncodeToString(preimage),
	}

	return &response, nil
}

func HandleDeriveKeyAndSignRequest(request *DeriveKeyAndSignRequest, seedBytes []byte) (*DeriveKeyAndSignResponse, error) {
	bitcoinNetwork, err := bitcoinNetworkConversion(request.BitcoinNetwork)
	if err != nil {
		return nil, err
	}

	var signatures []SignatureResponse
	for _, signingJob := range request.SigningJobs {
		log.Printf("Signing job: %s", signingJob.Id)

		signature, err := signSigningJob(signingJob, seedBytes, bitcoinNetwork)
		if err != nil {
			log.Printf("Error signing job %s: %s", signingJob.Id, err)
			return nil, err
		}
		signatures = append(signatures, SignatureResponse{
			Id:        signingJob.Id,
			Signature: signature.Signature,
		})
	}

	response := DeriveKeyAndSignResponse{
		Signatures: signatures,
	}

	return &response, nil
}

func bitcoinNetworkConversion(network objects.BitcoinNetwork) (lightspark_crypto.BitcoinNetwork, error) {
	switch network {
	case objects.BitcoinNetworkMainnet:
		return lightspark_crypto.Mainnet, nil
	case objects.BitcoinNetworkTestnet:
		return lightspark_crypto.Testnet, nil
	case objects.BitcoinNetworkRegtest:
		return lightspark_crypto.Regtest, nil
	default:
		return lightspark_crypto.BitcoinNetwork(0), errors.New("invalid network")
	}
}

func signSigningJob(signingJob SigningJob, seedBytes []byte, network lightspark_crypto.BitcoinNetwork) (objects.IdAndSignature, error) {
	addTweakBytes, err := signingJob.AddTweakBytes()
	if err != nil {
		return objects.IdAndSignature{}, err
	}
	mulTweakBytes, err := signingJob.MulTweakBytes()
	if err != nil {
		return objects.IdAndSignature{}, err
	}
	messageBytes, err := signingJob.MessageBytes()
	if err != nil {
		return objects.IdAndSignature{}, err
	}

	log.Printf("messageBytes: %s", hex.EncodeToString(messageBytes))

	signatureBytes, err := lightspark_crypto.DeriveKeyAndSign(
		seedBytes,
		network,
		messageBytes,
		signingJob.DerivationPath,
		true,
		&addTweakBytes,
		&mulTweakBytes)
	if err != nil {
		return objects.IdAndSignature{}, err
	}
	signature := objects.IdAndSignature{
		Id:        signingJob.Id,
		Signature: hex.EncodeToString(signatureBytes),
	}
	return signature, nil
}
