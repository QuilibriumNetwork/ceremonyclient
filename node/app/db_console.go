package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

var (
	textColor      = lipgloss.Color("#fff")
	primaryColor   = lipgloss.Color("#ff0070")
	secondaryColor = lipgloss.Color("#ff5c00")
	windowHeader   = lipgloss.NewStyle().
			Foreground(textColor).
			Padding(0, 1)
	unselectedListStyle = lipgloss.NewStyle().
				Foreground(textColor).
				Width(28).
				Padding(0, 1)
	navigatedListStyle = lipgloss.NewStyle().
				Foreground(textColor).
				Width(28).
				Bold(true).
				Padding(0, 1)
	selectedListStyle = lipgloss.NewStyle().
				Foreground(textColor).
				Background(primaryColor).
				Width(28).
				Padding(0, 1)
	statusBarStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(primaryColor)
	statusStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(primaryColor).
			Padding(0, 1)
	statusItemStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(secondaryColor).
			Padding(0, 1)
	docStyle = lipgloss.NewStyle().Padding(0)
	border   = lipgloss.Border{
		Top:         "─",
		Bottom:      "─",
		Left:        "│",
		Right:       "│",
		TopLeft:     "┌",
		TopRight:    "┐",
		BottomLeft:  "└",
		BottomRight: "┘",
	}
)

type DBConsole struct {
	nodeConfig *config.Config
}

func newDBConsole(nodeConfig *config.Config) (*DBConsole, error) {
	return &DBConsole{
		nodeConfig,
	}, nil
}

type model struct {
	filters          []string
	cursor           int
	selectedFilter   string
	conn             *grpc.ClientConn
	client           protobufs.NodeServiceClient
	peerId           string
	errorMsg         string
	frame            *protobufs.ClockFrame
	frames           []*protobufs.ClockFrame
	frameIndex       int
	grpcWarn         bool
	committed        bool
	lastChecked      int64
	owned            *big.Int
	unconfirmedOwned *big.Int
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.conn.GetState() == connectivity.Ready {
		if m.lastChecked < (time.Now().UnixMilli() - 10_000) {
			m.lastChecked = time.Now().UnixMilli()

			tokenBalance, err := FetchTokenBalance(m.client)
			if err == nil {
				m.owned = tokenBalance.Owned
				m.unconfirmedOwned = tokenBalance.UnconfirmedOwned
			}
		}
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up", "w":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "s":
			if m.cursor < len(m.filters)-1 {
				m.cursor++
			}
		case "left", "a":
			m.committed = false
			m.errorMsg = ""
			if m.frameIndex > 0 {
				m.frameIndex--
				if len(m.frames) != 0 && m.conn.GetState() == connectivity.Ready {
					filter, _ := hex.DecodeString(m.selectedFilter)
					selector, err := m.frames[m.frameIndex].GetSelector()
					if err != nil {
						m.errorMsg = err.Error()
						break
					}

					frameInfo, err := m.client.GetFrameInfo(
						context.Background(),
						&protobufs.GetFrameInfoRequest{
							Filter:      filter,
							FrameNumber: m.frames[m.frameIndex].FrameNumber,
						},
					)
					if err == nil && bytes.Equal(
						frameInfo.ClockFrame.Output,
						m.frames[m.frameIndex].Output,
					) {
						m.committed = true
						m.frame = frameInfo.ClockFrame
					} else {
						frameInfo, err := m.client.GetFrameInfo(
							context.Background(),
							&protobufs.GetFrameInfoRequest{
								Filter:      filter,
								FrameNumber: m.frames[m.frameIndex].FrameNumber,
								Selector:    selector.FillBytes(make([]byte, 32)),
							},
						)
						if err != nil {
							m.errorMsg = hex.EncodeToString(
								selector.Bytes(),
							) + ":" + err.Error()
							break
						}
						m.frame = frameInfo.ClockFrame
					}
				} else {
					m.errorMsg = "Not currently connected to node, cannot query."
				}
			} else {
				first := uint64(0)
				if len(m.frames) != 0 {
					first = m.frames[0].FrameNumber - 1
				}

				if first == 0 {
					break
				}

				max := uint64(17)
				if len(m.frames) != 0 {
					max = first
				}

				min := max - 16
				filter, _ := hex.DecodeString(m.selectedFilter)
				frames, err := m.client.GetFrames(
					context.Background(),
					&protobufs.GetFramesRequest{
						Filter:            filter,
						FromFrameNumber:   min,
						ToFrameNumber:     max + 1,
						IncludeCandidates: true,
					},
				)
				if err != nil {
					m.selectedFilter = ""
					m.errorMsg = err.Error()
					break
				}

				if frames.TruncatedClockFrames != nil {
					m.frames = frames.TruncatedClockFrames
					m.frameIndex = len(m.frames) - 1
					selector, err := m.frames[m.frameIndex].GetSelector()
					if err != nil {
						m.errorMsg = err.Error()
						break
					}

					frameInfo, err := m.client.GetFrameInfo(
						context.Background(),
						&protobufs.GetFrameInfoRequest{
							Filter:      filter,
							FrameNumber: m.frames[m.frameIndex].FrameNumber,
						},
					)
					if err == nil && bytes.Equal(
						frameInfo.ClockFrame.Output,
						m.frames[m.frameIndex].Output,
					) {
						m.committed = true
						m.frame = frameInfo.ClockFrame
					} else {
						frameInfo, err := m.client.GetFrameInfo(
							context.Background(),
							&protobufs.GetFrameInfoRequest{
								Filter:      filter,
								FrameNumber: m.frames[m.frameIndex].FrameNumber,
								Selector:    selector.FillBytes(make([]byte, 32)),
							},
						)
						if err != nil {
							m.errorMsg = err.Error()
							break
						}
						m.frame = frameInfo.ClockFrame
					}
				}
			}
		case "right", "d":
			m.committed = false
			m.errorMsg = ""
			if m.frameIndex < len(m.frames)-1 {
				m.frameIndex++
				if len(m.frames) != 0 && m.conn.GetState() == connectivity.Ready {
					filter, _ := hex.DecodeString(m.selectedFilter)
					selector, err := m.frames[m.frameIndex].GetSelector()
					if err != nil {
						m.errorMsg = err.Error()
						break
					}

					frameInfo, err := m.client.GetFrameInfo(
						context.Background(),
						&protobufs.GetFrameInfoRequest{
							Filter:      filter,
							FrameNumber: m.frames[m.frameIndex].FrameNumber,
						},
					)
					if err == nil && bytes.Equal(
						frameInfo.ClockFrame.Output,
						m.frames[m.frameIndex].Output,
					) {
						m.committed = true
						m.frame = frameInfo.ClockFrame
					} else {
						frameInfo, err := m.client.GetFrameInfo(
							context.Background(),
							&protobufs.GetFrameInfoRequest{
								Filter:      filter,
								FrameNumber: m.frames[m.frameIndex].FrameNumber,
								Selector:    selector.FillBytes(make([]byte, 32)),
							},
						)
						if err != nil {
							m.errorMsg = hex.EncodeToString(
								selector.Bytes(),
							) + ":" + err.Error()
							break
						}
						m.frame = frameInfo.ClockFrame
					}
				} else {
					m.errorMsg = "Not currently connected to node, cannot query."
				}
			} else {
				min := uint64(1)
				if len(m.frames) != 0 {
					min = m.frames[len(m.frames)-1].FrameNumber + 1
				}

				max := min + 16
				filter, _ := hex.DecodeString(m.selectedFilter)
				frames, err := m.client.GetFrames(
					context.Background(),
					&protobufs.GetFramesRequest{
						Filter:            filter,
						FromFrameNumber:   min,
						ToFrameNumber:     max,
						IncludeCandidates: true,
					},
				)
				if err != nil {
					m.selectedFilter = ""
					m.errorMsg = err.Error()
					break
				}

				if frames.TruncatedClockFrames != nil {
					m.frames = frames.TruncatedClockFrames
					m.frameIndex = 0
					selector, err := m.frames[m.frameIndex].GetSelector()
					if err != nil {
						m.errorMsg = err.Error()
						break
					}

					frameInfo, err := m.client.GetFrameInfo(
						context.Background(),
						&protobufs.GetFrameInfoRequest{
							Filter:      filter,
							FrameNumber: m.frames[m.frameIndex].FrameNumber,
						},
					)
					if err == nil && bytes.Equal(
						frameInfo.ClockFrame.Output,
						m.frames[m.frameIndex].Output,
					) {
						m.committed = true
						m.frame = frameInfo.ClockFrame
					} else {
						frameInfo, err := m.client.GetFrameInfo(
							context.Background(),
							&protobufs.GetFrameInfoRequest{
								Filter:      filter,
								FrameNumber: m.frames[m.frameIndex].FrameNumber,
								Selector:    selector.FillBytes(make([]byte, 32)),
							},
						)
						if err != nil {
							m.errorMsg = err.Error()
							break
						}
						m.frame = frameInfo.ClockFrame
					}
				}
			}
		case "enter", " ":
			m.errorMsg = ""
			m.frame = nil
			m.committed = false
			if m.conn.GetState() == connectivity.Ready {
				if m.selectedFilter != m.filters[m.cursor] {
					m.selectedFilter = m.filters[m.cursor]
					m.frames = []*protobufs.ClockFrame{}
				}

				min := uint64(1)
				if len(m.frames) != 0 {
					min = m.frames[len(m.frames)-1].FrameNumber + 1
				}

				max := min + 16
				filter, _ := hex.DecodeString(m.selectedFilter)
				frames, err := m.client.GetFrames(
					context.Background(),
					&protobufs.GetFramesRequest{
						Filter:            filter,
						FromFrameNumber:   min,
						ToFrameNumber:     max,
						IncludeCandidates: true,
					},
				)
				if err != nil {
					m.selectedFilter = ""
					m.errorMsg = err.Error()
					break
				}

				if frames.TruncatedClockFrames != nil {
					m.frames = frames.TruncatedClockFrames
					m.frameIndex = 0
					selector, err := m.frames[m.frameIndex].GetSelector()
					if err != nil {
						m.errorMsg = err.Error()
						break
					}

					frameInfo, err := m.client.GetFrameInfo(
						context.Background(),
						&protobufs.GetFrameInfoRequest{
							Filter:      filter,
							FrameNumber: m.frames[m.frameIndex].FrameNumber,
						},
					)
					if err == nil && bytes.Equal(
						frameInfo.ClockFrame.Output,
						m.frames[m.frameIndex].Output,
					) {
						m.committed = true
						m.frame = frameInfo.ClockFrame
					} else {
						frameInfo, err := m.client.GetFrameInfo(
							context.Background(),
							&protobufs.GetFrameInfoRequest{
								Filter:      filter,
								FrameNumber: m.frames[m.frameIndex].FrameNumber,
								Selector:    selector.FillBytes(make([]byte, 32)),
							},
						)
						if err != nil {
							m.errorMsg = err.Error()
							break
						}
						m.frame = frameInfo.ClockFrame
					}
				}
			} else {
				m.errorMsg = "Not currently connected to node, cannot query."
			}
		}
	}

	return m, nil
}

func (m model) View() string {
	physicalWidth, physicalHeight, _ := term.GetSize(int(os.Stdout.Fd()))
	doc := strings.Builder{}

	window := lipgloss.NewStyle().
		Border(border, true).
		BorderForeground(primaryColor).
		Padding(0, 1)

	list := []string{}
	for i, item := range m.filters {
		str := item[0:12] + ".." + item[len(item)-12:]
		if m.selectedFilter == item {
			list = append(list, selectedListStyle.Render(str))
		} else if i == m.cursor {
			list = append(list, navigatedListStyle.Render(str))
		} else {
			list = append(list, unselectedListStyle.Render(str))
		}
	}

	w := lipgloss.Width

	statusKey := statusItemStyle.Render("STATUS")
	info := statusStyle.Render("(Press Ctrl-C or Q to quit)")
	onlineStatus := "gRPC Not Enabled, Please Configure"
	if !m.grpcWarn {
		switch m.conn.GetState() {
		case connectivity.Connecting:
			onlineStatus = "CONNECTING"
		case connectivity.Idle:
			onlineStatus = "IDLE"
		case connectivity.Shutdown:
			onlineStatus = "SHUTDOWN"
		case connectivity.TransientFailure:
			onlineStatus = "DISCONNECTED"
		default:
			onlineStatus = "CONNECTED"
		}
	}

	ownedVal := statusItemStyle.Copy().
		Render("Owned: " + m.owned.String())
	if m.owned.Cmp(big.NewInt(-1)) == 0 {
		ownedVal = statusItemStyle.Copy().
			Render("")
	}

	unconfirmedOwnedVal := statusItemStyle.Copy().
		Render("Unconfirmed: " + m.unconfirmedOwned.String())
	if m.unconfirmedOwned.Cmp(big.NewInt(-1)) == 0 {
		unconfirmedOwnedVal = statusItemStyle.Copy().
			Render("")
	}
	peerIdVal := statusItemStyle.Render(m.peerId)
	statusVal := statusBarStyle.Copy().
		Width(physicalWidth-w(statusKey)-w(info)-w(peerIdVal)-w(ownedVal)-
			w(unconfirmedOwnedVal)).
		Padding(0, 1).
		Render(onlineStatus)

	bar := lipgloss.JoinHorizontal(lipgloss.Top,
		statusKey,
		statusVal,
		info,
		peerIdVal,
		ownedVal,
		unconfirmedOwnedVal,
	)

	explorerContent := ""

	if m.errorMsg != "" {
		explorerContent = m.errorMsg
	} else if m.frame != nil {
		selector, err := m.frame.GetSelector()
		if err != nil {
			panic(err)
		}
		committed := "Unconfirmed"
		if m.committed {
			committed = "Confirmed"
		}
		explorerContent = fmt.Sprintf(
			"Frame %d (Selector: %x, %s):\n\tParent: %x\n\tVDF Proof: %x\n",
			m.frame.FrameNumber,
			selector.Bytes(),
			committed,
			m.frame.ParentSelector,
			m.frame.Input[:516],
		)

		for i := 0; i < len(m.frame.Input[516:])/74; i++ {
			commit := m.frame.Input[516+(i*74) : 516+((i+1)*74)]
			explorerContent += fmt.Sprintf(
				"\tCommitment %+x\n",
				commit,
			)
			explorerContent += fmt.Sprintf(
				"\t\tType: %s\n",
				m.frame.AggregateProofs[i].InclusionCommitments[0].TypeUrl,
			)
			switch m.frame.AggregateProofs[i].InclusionCommitments[0].TypeUrl {
			case protobufs.IntrinsicExecutionOutputType:
				explorerContent += "Application: Ceremony\n"
				app, err := application.MaterializeApplicationFromFrame(m.frame)
				if err != nil {
					explorerContent += "Error: " + err.Error() + "\n"
					continue
				}

				total := new(big.Int)
				if app.RewardTrie.Root == nil ||
					(app.RewardTrie.Root.External == nil &&
						app.RewardTrie.Root.Internal == nil) {
					explorerContent += "Total Rewards: 0 QUIL\n"
					continue
				}

				limbs := []*tries.RewardInternalNode{}
				if app.RewardTrie.Root.Internal != nil {
					limbs = append(limbs, app.RewardTrie.Root.Internal)
				} else {
					total = total.Add(
						total,
						new(big.Int).SetUint64(app.RewardTrie.Root.External.Total),
					)
				}

				for len(limbs) != 0 {
					nextLimbs := []*tries.RewardInternalNode{}
					for _, limb := range limbs {
						for _, child := range limb.Child {
							child := child
							if child.Internal != nil {
								nextLimbs = append(nextLimbs, child.Internal)
							} else {
								total = total.Add(
									total,
									new(big.Int).SetUint64(child.External.Total),
								)
							}
						}
					}
					limbs = nextLimbs
				}

				explorerContent += "Total Rewards: " + total.String() + " QUIL\n"

				state := app.LobbyState.String()
				explorerContent += "Round State: " + state + "\n"

				switch app.LobbyState {
				case application.CEREMONY_APPLICATION_STATE_OPEN:
					explorerContent += "Joins: \n"

					for _, join := range app.LobbyJoins {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							join.PublicKeySignatureEd448.PublicKey.KeyValue,
						) + "\n"
					}

					explorerContent += "Preferred Next Round Participants: \n"

					for _, next := range app.NextRoundPreferredParticipants {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							next.KeyValue,
						) + "\n"
					}

					explorerContent += fmt.Sprintf(
						"State Transition Counter: %d\n",
						app.StateCount,
					)
				case application.CEREMONY_APPLICATION_STATE_IN_PROGRESS:
					explorerContent += fmt.Sprintf("Sub-Round: %d\n", app.RoundCount)
					explorerContent += "Participants: \n"

					for _, active := range app.ActiveParticipants {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							active.PublicKeySignatureEd448.PublicKey.KeyValue,
						) + "\n"
					}

					explorerContent += "Latest Seen: \n"

					for _, latest := range app.LatestSeenProverAttestations {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							latest.SeenProverKey.KeyValue,
						) + " seen by " + base64.StdEncoding.EncodeToString(
							latest.ProverSignature.PublicKey.KeyValue,
						) + "\n"
					}

					explorerContent += "Dropped: \n"

					for _, dropped := range app.DroppedParticipantAttestations {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							dropped.DroppedProverKey.KeyValue,
						) + " confirmed by " + base64.StdEncoding.EncodeToString(
							dropped.ProverSignature.PublicKey.KeyValue,
						) + "\n"
					}

					explorerContent += "Preferred Next Round Participants: \n"

					for _, next := range app.NextRoundPreferredParticipants {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							next.KeyValue,
						) + "\n"
					}
				case application.CEREMONY_APPLICATION_STATE_FINALIZING:
					explorerContent += fmt.Sprintf(
						"Confirmed Shares: %d\n",
						len(app.TranscriptShares),
					)
					explorerContent += "Participants: \n"

					for _, active := range app.ActiveParticipants {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							active.PublicKeySignatureEd448.PublicKey.KeyValue,
						) + "\n"
					}

					explorerContent += "Latest Seen: \n"

					for _, latest := range app.LatestSeenProverAttestations {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							latest.SeenProverKey.KeyValue,
						) + " seen by " + base64.StdEncoding.EncodeToString(
							latest.ProverSignature.PublicKey.KeyValue,
						) + "\n"
					}

					explorerContent += "Dropped: \n"

					for _, dropped := range app.DroppedParticipantAttestations {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							dropped.DroppedProverKey.KeyValue,
						) + " confirmed by " + base64.StdEncoding.EncodeToString(
							dropped.ProverSignature.PublicKey.KeyValue,
						) + "\n"
					}

					explorerContent += "Preferred Next Round Participants: \n"

					for _, next := range app.NextRoundPreferredParticipants {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							next.KeyValue,
						) + "\n"
					}
				case application.CEREMONY_APPLICATION_STATE_VALIDATING:
					explorerContent += fmt.Sprintf(
						"G1 Powers: %d\n", len(app.UpdatedTranscript.G1Powers),
					)
					explorerContent += "Preferred Next Round Participants: \n"
					for _, next := range app.NextRoundPreferredParticipants {
						explorerContent += "\t" + base64.StdEncoding.EncodeToString(
							next.KeyValue,
						) + "\n"
					}
				}
			}
		}
	} else {
		explorerContent = logoVersion(physicalWidth - 34)
	}

	doc.WriteString(
		lipgloss.JoinVertical(
			lipgloss.Left,
			lipgloss.JoinHorizontal(
				lipgloss.Top,
				lipgloss.JoinVertical(
					lipgloss.Left,
					windowHeader.Render("Filters (Up/Down, Enter)"),
					window.Width(30).Height(physicalHeight-4).Render(lipgloss.JoinVertical(lipgloss.Left, list...)),
				),
				lipgloss.JoinVertical(
					lipgloss.Left,
					windowHeader.Render("Explorer (Left/Right)"),
					window.Width(physicalWidth-34).Height(physicalHeight-4).Render(explorerContent),
				),
			),
			statusBarStyle.Width(physicalWidth).Render(bar),
		),
	)

	if physicalWidth > 0 {
		docStyle = docStyle.MaxWidth(physicalWidth)
		docStyle = docStyle.MaxHeight(physicalHeight)
	}

	return docStyle.Render(doc.String())
}

func consoleModel(
	conn *grpc.ClientConn,
	nodeConfig *config.Config,
	grpcWarn bool,
) model {
	peerPrivKey, err := hex.DecodeString(nodeConfig.P2P.PeerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(errors.Wrap(err, "error getting peer id"))
	}

	return model{
		filters: []string{
			hex.EncodeToString([]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			}),
			hex.EncodeToString(append(
				p2p.GetBloomFilter(application.CEREMONY_ADDRESS, 256, 3),
				p2p.GetBloomFilterIndices(application.CEREMONY_ADDRESS, 65536, 24)...,
			)),
		},
		cursor:           0,
		conn:             conn,
		client:           protobufs.NewNodeServiceClient(conn),
		owned:            big.NewInt(-1),
		unconfirmedOwned: big.NewInt(-1),
		peerId:           id.String(),
		grpcWarn:         grpcWarn,
	}
}

var defaultGrpcAddress = "localhost:8337"

// Connect to the node via GRPC
func ConnectToNode(nodeConfig *config.Config) (*grpc.ClientConn, error) {
	addr := defaultGrpcAddress
	if nodeConfig.ListenGRPCMultiaddr != "" {
		ma, err := multiaddr.NewMultiaddr(nodeConfig.ListenGRPCMultiaddr)
		if err != nil {
			panic(err)
		}

		_, addr, err = mn.DialArgs(ma)
		if err != nil {
			panic(err)
		}
	}

	return grpc.Dial(
		addr,
		grpc.WithTransportCredentials(
			insecure.NewCredentials(),
		),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(600*1024*1024),
			grpc.MaxCallRecvMsgSize(600*1024*1024),
		),
	)
}

type TokenBalance struct {
	Owned            *big.Int
	UnconfirmedOwned *big.Int
}

func FetchTokenBalance(client protobufs.NodeServiceClient) (TokenBalance, error) {
	info, err := client.GetTokenInfo(
		context.Background(),
		&protobufs.GetTokenInfoRequest{},
	)
	if err != nil {
		return TokenBalance{}, errors.Wrap(err, "error getting token info")
	}

	conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)

	owned := new(big.Int).SetBytes(info.OwnedTokens)
	owned.Div(owned, conversionFactor)

	unconfirmedOwned := new(big.Int).SetBytes(info.UnconfirmedOwnedTokens)
	unconfirmedOwned.Div(unconfirmedOwned, conversionFactor)

	return TokenBalance{
		Owned:            owned,
		UnconfirmedOwned: unconfirmedOwned,
	}, nil
}

// Runs the DB console
func (c *DBConsole) Run() {
	conn, err := ConnectToNode(c.nodeConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	grpcWarn := c.nodeConfig.ListenGRPCMultiaddr == ""

	p := tea.NewProgram(consoleModel(conn, c.nodeConfig, grpcWarn))
	if _, err := p.Run(); err != nil {
		panic(err)
	}
}

func logoVersion(width int) string {
	var out string

	if width >= 83 {
		out = "                                   %#########\n"
		out += "                          #############################\n"
		out += "                    ########################################&\n"
		out += "                 ###############################################\n"
		out += "             &#####################%        %######################\n"
		out += "           #################                         #################\n"
		out += "         ###############                                 ###############\n"
		out += "       #############                                        ##############\n"
		out += "     #############                                             ############&\n"
		out += "    ############                                                 ############\n"
		out += "   ###########                     ##########                     &###########\n"
		out += "  ###########                    ##############                     ###########\n"
		out += " ###########                     ##############                      ##########&\n"
		out += " ##########                      ##############                       ##########\n"
		out += "%##########                        ##########                         ##########\n"
		out += "##########&                                                           ##########\n"
		out += "##########                                                            &#########\n"
		out += "##########&                   #######      #######                    ##########\n"
		out += " ##########                &#########################                 ##########\n"
		out += " ##########              ##############% ##############              &##########\n"
		out += " %##########          &##############      ###############           ##########\n"
		out += "  ###########       ###############           ##############%       ###########\n"
		out += "   ###########&       ##########                ###############       ########\n"
		out += "    ############         #####                     ##############%       ####\n"
		out += "      ############                                   ###############\n"
		out += "       ##############                                   ##############%\n"
		out += "         ###############                                  ###############\n"
		out += "           #################&                                ##############%\n"
		out += "              #########################&&&#############        ###############\n"
		out += "                 ########################################%        ############\n"
		out += "                     #######################################        ########\n"
		out += "                          #############################                ##\n"
		out += " \n"
		out += "                         Quilibrium Node - v1.2.4 – Dawn\n"
		out += " \n"
		out += "                                   DB Console\n"
	} else {
		out = "Quilibrium Node - v1.2.4 – Dawn - DB Console\n"
	}
	return out
}
