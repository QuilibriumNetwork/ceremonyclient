FROM golang:1.20.14-alpine3.19

ARG GIT_COMMIT=unspecified

LABEL org.opencontainers.image.title="Quilibrium Network Node"
LABEL org.opencontainers.image.description="Quilibrium is a decentralized alternative to platform as a service providers."
LABEL org.opencontainers.image.vendor=Quilibrium
LABEL org.opencontainers.image.url=https://quilibrium.com/
LABEL org.opencontainers.image.documentation=https://quilibrium.com/docs
LABEL org.opencontainers.image.revision=$GIT_COMMIT

ENV GOEXPERIMENT=arenas

WORKDIR /opt/ceremonyclient

COPY . . 

WORKDIR /opt/ceremonyclient/node

RUN go mod download && go mod verify
RUN go build ./...

ENTRYPOINT ["go", "run", "./..."]
