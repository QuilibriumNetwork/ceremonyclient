package cmd

import (
	"encoding/hex"
	"strings"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var proverPauseCmd = &cobra.Command{
	Use:   "pause",
	Short: "Pauses a prover",
	Long: `Pauses a prover (use in emergency when a worker isn't coming back online):
	
	pause <Filter>
	
	Filter – the hex bitstring of the filter to pause for
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			panic("invalid arguments")
		}

		logger, err := zap.NewProduction()
		pubsub := p2p.NewBlossomSub(NodeConfig.P2P, logger)
		intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)
		pubsub.Subscribe(
			intrinsicFilter,
			func(message *pb.Message) error { return nil },
		)
		key, err := GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}

		payload := []byte("pause")
		filterHex, _ := strings.CutPrefix(args[0], "0x")
		filter, err := hex.DecodeString(filterHex)
		if err != nil {
			panic(err)
		}

		payload = append(payload, filter...)

		sig, err := key.Sign(payload)
		if err != nil {
			panic(err)
		}

		pub, err := key.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

		err = publishMessage(
			key,
			pubsub,
			intrinsicFilter,
			&protobufs.AnnounceProverPause{
				Filter: filter,
				PublicKeySignatureEd448: &protobufs.Ed448Signature{
					Signature: sig,
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: pub,
					},
				},
			},
		)
		if err != nil {
			panic(err)
		}
	},
}

func publishMessage(
	key crypto.PrivKey,
	pubsub p2p.PubSub,
	filter []byte,
	message proto.Message,
) error {
	any := &anypb.Any{}
	if err := any.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	any.TypeUrl = strings.Replace(
		any.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(any)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	pub, err := key.GetPublic().Raw()
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	pbi, err := poseidon.HashBytes(pub)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	provingKeyAddress := pbi.FillBytes(make([]byte, 32))

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: provingKeyAddress,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return pubsub.PublishToBitmask(filter, data)
}

func init() {
	proverCmd.AddCommand(proverPauseCmd)
}
