FROM golang:1.18

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

# Add an entry to .bash_history so we can just run `make dev` and hit up to test the cli
RUN echo 'go run ./... test-voucher.hex' >> ~/.bash_history

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o ceremony-client

CMD ./ceremony-client