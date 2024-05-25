FROM golang:1.20.14-bookworm

ENV GOEXPERIMENT=arenas
ENV QUILIBRIUM_DOCKER_CONTAINER=true

ARG USER_NAME=default
ARG UID=1000
ARG GID=1000

RUN groupadd -g ${GID} ${USER_NAME} \
    && useradd -u ${UID} -g ${USER_NAME} -s /bin/bash ${USER_NAME}

RUN sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin
RUN apt-get update && apt-get install git

USER ${USER_NAME}

WORKDIR /home/${USER_NAME}
