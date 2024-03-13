FROM golang:1.20.14-alpine3.19 as build

ENV GOEXPERIMENT=arenas

WORKDIR /opt/ceremonyclient

COPY . .

WORKDIR /opt/ceremonyclient/node

RUN go install ./...
RUN go install github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.8.9

FROM alpine:3.19

ARG GIT_REPO
ARG GIT_BRANCH
ARG GIT_COMMIT

ENV GOEXPERIMENT=arenas

LABEL org.opencontainers.image.title="Quilibrium Network Node"
LABEL org.opencontainers.image.description="Quilibrium is a decentralized alternative to platform as a service providers."
LABEL org.opencontainers.image.vendor=Quilibrium
LABEL org.opencontainers.image.url=https://quilibrium.com/
LABEL org.opencontainers.image.documentation=https://quilibrium.com/docs
LABEL org.opencontainers.image.source=$GIT_REPO
LABEL org.opencontainers.image.ref.name=$GIT_BRANCH
LABEL org.opencontainers.image.revision=$GIT_COMMIT

COPY --from=build /go/bin/node /usr/local/bin
COPY --from=build /go/bin/grpcurl /usr/local/bin
COPY --from=build /opt/ceremonyclient/node/ceremony.json /root
COPY --from=build /opt/ceremonyclient/node/retroactive_peers.json /root

WORKDIR /root

ENTRYPOINT ["node"]
