ARG GIT_REPO=https://github.com/QuilibriumNetwork/ceremonyclient
ARG GIT_BRANCH=main
ARG GIT_COMMIT=HEAD

FROM golang:1.20.14-alpine3.19 as build

ARG GIT_REPO
ARG GIT_BRANCH
ARG GIT_COMMIT

ENV GOEXPERIMENT=arenas

RUN apk update
RUN apk add git

WORKDIR /opt/quilibrium

RUN git clone -b $GIT_BRANCH $GIT_REPO

WORKDIR /opt/quilibrium/ceremonyclient

RUN git checkout $GIT_COMMIT

WORKDIR /opt/quilibrium/ceremonyclient/node

RUN go install ./...
RUN go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

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
LABEL git-branch=$GIT_BRANCH
LABEL org.opencontainers.image.revision=$GIT_COMMIT

COPY --from=build /go/bin/node /usr/local/bin
COPY --from=build /go/bin/grpcurl /usr/local/bin
COPY --from=build /opt/quilibrium/ceremonyclient/node/ceremony.json /root
COPY --from=build /opt/quilibrium/ceremonyclient/node/retroactive_peers.json /root

WORKDIR /root

ENTRYPOINT ["node"]
