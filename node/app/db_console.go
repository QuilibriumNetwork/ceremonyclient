package app

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type DBConsole struct {
	clockStore store.ClockStore
}

func newDBConsole(
	clockStore store.ClockStore,
) (*DBConsole, error) {
	return &DBConsole{
		clockStore,
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
		case "show frames":
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
		default:
			fmt.Printf("unknown command %s\n", cmd)
		}
	}
}
