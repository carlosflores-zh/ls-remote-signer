run-webhook:
	go run remote-signing-server/*.go

build-client:
	go build -o cli client/client.go