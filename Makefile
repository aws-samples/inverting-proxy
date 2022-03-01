
buildagent: vet
	go build -o ${GOPATH}/bin/proxy-forwarding-agent ./agent/agent.go
	go mod tidy

buildserver: vet
	go build -o ${GOPATH}/bin/inverting-proxy ./server/server.go
	go mod tidy

vet:	deps
	go vet ./agent/banner/...
	go vet ./agent/metrics/...
	go vet ./agent/sessions/...
	go vet ./agent/utils/...
	go vet ./agent/websockets/...
	go vet ./agent/agent.go
	go mod tidy

deps:	fmt
	go get ./...
	go mod tidy

fmt:	FORCE
	gofmt -w ./
	go mod tidy


FORCE:
