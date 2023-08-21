package circuitv2

//go:generate protoc --proto_path=$PWD:$PWD/../../.. --go_out=. --go_opt=Mpb/circuit.proto=./pb pb/circuit.proto
//go:generate protoc --proto_path=$PWD:$PWD/../../.. --go_out=. --go_opt=Mpb/voucher.proto=./pb pb/voucher.proto
