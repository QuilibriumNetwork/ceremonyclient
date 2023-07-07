PB = $(wildcard *.proto)
GO = $(PB:.proto=.pb.go)

all: $(GO)

%.pb.go: %.proto
		protoc --go_out=paths=source_relative:. $<

clean:
		rm -f *.pb.go
		rm -f *.go