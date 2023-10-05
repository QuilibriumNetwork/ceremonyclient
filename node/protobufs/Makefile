PB = $(wildcard *.proto)
GO = $(PB:.proto=.pb.go)
PWD = $(pwd)

all: $(GO)

%.pb.go: %.proto
		protoc -I=. --go-grpc_out=paths=source_relative:. --go_out=paths=source_relative:. *.proto

clean:
		rm -f *.pb.go
		rm -f *.go