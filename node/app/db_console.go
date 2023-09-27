package app

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type DBConsole struct {
	clockStore     store.ClockStore
	dataProofStore store.DataProofStore
}

func newDBConsole(
	clockStore store.ClockStore,
	dataProofStore store.DataProofStore,
) (*DBConsole, error) {
	return &DBConsole{
		clockStore,
		dataProofStore,
	}, nil
}

// Runs the DB console, this is meant for simple debugging, not production use.
func (c *DBConsole) Run() {
	for {
		fmt.Printf("db> ")

		reader := bufio.NewReader(os.Stdin)
		s, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}

		cmd := strings.Trim(s, "\n")
		switch cmd {
		case "quit":
			return
		case "show master frames":
			earliestFrame, err := c.clockStore.GetEarliestMasterClockFrame([]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			})
			if err != nil {
				panic(err)
			}

			latestFrame, err := c.clockStore.GetLatestMasterClockFrame([]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			})
			if err != nil {
				panic(err)
			}

			fmt.Printf(
				"earliest: %d, latest: %d\n",
				earliestFrame.FrameNumber,
				latestFrame.FrameNumber,
			)

			fmt.Printf(
				"Genesis Frame:\n\tVDF Proof: %x\n",
				earliestFrame.Input[:516],
			)

			iter, err := c.clockStore.RangeMasterClockFrames(
				[]byte{
					0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				},
				earliestFrame.FrameNumber,
				latestFrame.FrameNumber,
			)
			if err != nil {
				panic(err)
			}

			for iter.First(); iter.Valid(); iter.Next() {
				value, err := iter.Value()
				if err != nil {
					panic(err)
				}

				selector, err := value.GetSelector()
				if err != nil {
					panic(err)
				}

				fmt.Printf(
					"Frame %d (Selector: %x):\n\tParent: %x\n\tVDF Proof: %x\n\n",
					value.FrameNumber,
					selector.Bytes(),
					value.ParentSelector,
					value.Input[:516],
				)
			}

			if err := iter.Close(); err != nil {
				panic(err)
			}
		case "show ceremony frames":
			earliestFrame, err := c.clockStore.GetEarliestDataClockFrame(
				application.CEREMONY_ADDRESS,
			)
			if err != nil {
				panic(errors.Wrap(err, "earliest"))
			}

			latestFrame, err := c.clockStore.GetLatestDataClockFrame(
				application.CEREMONY_ADDRESS,
				nil,
			)
			if err != nil {
				panic(errors.Wrap(err, "latest"))
			}

			fmt.Printf(
				"earliest: %d, latest: %d\n",
				earliestFrame.FrameNumber,
				latestFrame.FrameNumber,
			)

			fmt.Printf(
				"Genesis Frame:\n\tVDF Proof: %x\n",
				earliestFrame.Input[:516],
			)

			iter, err := c.clockStore.RangeDataClockFrames(
				application.CEREMONY_ADDRESS,
				earliestFrame.FrameNumber+1,
				latestFrame.FrameNumber,
			)
			if err != nil {
				panic(err)
			}

			for iter.First(); iter.Valid(); iter.Next() {
				value, err := iter.Value()
				if err != nil {
					panic(err)
				}

				selector, err := value.GetSelector()
				if err != nil {
					panic(err)
				}

				fmt.Printf(
					"Frame %d (Selector: %x):\n\tParent: %x\n\tVDF Proof: %x\n",
					value.FrameNumber,
					selector.Bytes(),
					value.ParentSelector,
					value.Input[:516],
				)

				for i := 0; i < len(value.Input[516:])/74; i++ {
					commit := value.Input[516+(i*74) : 516+((i+1)*74)]
					fmt.Printf(
						"\tCommitment %+x\n",
						commit,
					)
					fmt.Printf(
						"\t\tType: %s\n",
						value.AggregateProofs[i].InclusionCommitments[0].TypeUrl,
					)
					b, _ := proto.Marshal(value.AggregateProofs[i])
					hash := sha3.Sum256(b)
					fmt.Printf("\t\tAP Hash: %+x\n", hash)
				}

				fmt.Println()
			}

			if err := iter.Close(); err != nil {
				panic(err)
			}
		default:
			fmt.Printf("unknown command %s\n", cmd)
		}
	}
}
