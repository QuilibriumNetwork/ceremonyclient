FROM golang:1.20

ENV GOEXPERIMENT=arenas

WORKDIR /opt/ceremonyclient

COPY . . 

WORKDIR /opt/ceremonyclient/node

RUN go mod download && go mod verify

CMD ["go", "run", "./..."]

