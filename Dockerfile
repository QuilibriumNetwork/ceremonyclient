FROM golang:1.20-alpine

ENV GOEXPERIMENT=arenas

WORKDIR /opt/ceremonyclient

COPY . . 

WORKDIR /opt/ceremonyclient/node

RUN go mod download && go mod verify
RUN go build ./...

ENTRYPOINT ["go", "run", "./..."]
