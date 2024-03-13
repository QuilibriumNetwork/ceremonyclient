FROM golang:1.18 AS builder
# Install gomarkdoc
RUN GO111MODULE=on go get -u github.com/princjef/gomarkdoc/cmd/gomarkdoc@v1.1.0

# Install rust and build spdx
COPY . /kryptology
WORKDIR /kryptology

RUN apt update && apt -y install --no-install-recommends curl && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs  -- | sh -s -- -y
RUN /root/.cargo/bin/cargo build --release --manifest-path=./cmd/spdx/Cargo.toml && \
    cp ./cmd/spdx/target/release/spdx /usr/bin/ && \
    chmod 755 /usr/bin/spdx
