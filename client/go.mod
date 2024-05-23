module source.quilibrium.com/quilibrium/monorepo/client

go 1.20

replace github.com/libp2p/go-libp2p => ../go-libp2p

replace source.quilibrium.com/quilibrium/monorepo/node => ../node

replace source.quilibrium.com/quilibrium/monorepo/nekryptology => ../nekryptology

require (
	github.com/iden3/go-iden3-crypto v0.0.15
	github.com/mr-tron/base58 v1.2.0
	github.com/stretchr/testify v1.8.4
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/btcsuite/btcd v0.21.0-beta.0.20201114000516-e9c7a5ac6401 // indirect
	github.com/bwesterb/go-ristretto v1.2.3 // indirect
	github.com/consensys/gnark-crypto v0.5.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	source.quilibrium.com/quilibrium/monorepo/nekryptology v0.0.0-00010101000000-000000000000 // indirect
)

require (
	github.com/cloudflare/circl v1.3.8
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/libp2p/go-libp2p v0.33.2
	github.com/pkg/errors v0.9.1
	github.com/shopspring/decimal v1.4.0
	github.com/spf13/cobra v1.8.0
	github.com/spf13/pflag v1.0.5 // indirect
	go.uber.org/zap v1.27.0
	google.golang.org/protobuf v1.32.0 // indirect
	source.quilibrium.com/quilibrium/monorepo/node v1.14.17
)
