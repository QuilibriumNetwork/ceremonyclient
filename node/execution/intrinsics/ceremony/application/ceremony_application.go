package application

import (
	"bytes"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

var ErrInvalidStateTransition = errors.New("invalid state transition")

type CeremonyApplicationState int

var CEREMONY_ADDRESS = []byte{
	// SHA3-256("q_kzg_ceremony")
	0x34, 0x00, 0x1b, 0xe7, 0x43, 0x2c, 0x2e, 0x66,
	0x69, 0xad, 0xa0, 0x27, 0x97, 0x88, 0x68, 0x2a,
	0xb9, 0xf6, 0x26, 0x71, 0xb1, 0xb5, 0x38, 0xab,
	0x99, 0x50, 0x46, 0x94, 0xd9, 0x81, 0xcb, 0xd3,
}

const (
	CEREMONY_APPLICATION_STATE_OPEN CeremonyApplicationState = iota
	CEREMONY_APPLICATION_STATE_IN_PROGRESS
	CEREMONY_APPLICATION_STATE_FINALIZING
	CEREMONY_APPLICATION_STATE_VALIDATING
)

func (s CeremonyApplicationState) String() string {
	switch s {
	case CEREMONY_APPLICATION_STATE_OPEN:
		return "OPEN"
	case CEREMONY_APPLICATION_STATE_IN_PROGRESS:
		return "IN PROGRESS"
	case CEREMONY_APPLICATION_STATE_FINALIZING:
		return "FINALIZING"
	case CEREMONY_APPLICATION_STATE_VALIDATING:
		return "VALIDATING"
	default:
		return "UNKNOWN"
	}
}

type CeremonyApplication struct {
	StateCount                     uint64
	RoundCount                     uint64
	LobbyState                     CeremonyApplicationState
	ActiveParticipants             []*protobufs.CeremonyLobbyJoin
	NextRoundPreferredParticipants []*protobufs.Ed448PublicKey
	LatestSeenProverAttestations   []*protobufs.CeremonySeenProverAttestation
	DroppedParticipantAttestations []*protobufs.CeremonyDroppedProverAttestation
	LobbyJoins                     []*protobufs.CeremonyLobbyJoin
	TranscriptRoundAdvanceCommits  []*protobufs.CeremonyAdvanceRound
	FinalCommits                   []*protobufs.CeremonyTranscriptCommit
	LatestTranscript               *protobufs.CeremonyTranscript
	RewardTrie                     *tries.RewardCritbitTrie
	UpdatedTranscript              *protobufs.CeremonyTranscript
	TranscriptShares               []*protobufs.CeremonyTranscriptShare
}

func (a *CeremonyApplication) Equals(b *CeremonyApplication) bool {
	if a.StateCount != b.StateCount {
		return false
	}

	if a.RoundCount != b.RoundCount {
		return false
	}

	if a.LobbyState != b.LobbyState {
		return false
	}

	if len(a.ActiveParticipants) != len(b.ActiveParticipants) {
		return false
	}

	for i := range a.ActiveParticipants {
		if !bytes.Equal(
			a.ActiveParticipants[i].PublicKeySignatureEd448.PublicKey.KeyValue,
			b.ActiveParticipants[i].PublicKeySignatureEd448.PublicKey.KeyValue,
		) {
			return false
		}

		if !bytes.Equal(
			a.ActiveParticipants[i].IdentityKey.KeyValue,
			b.ActiveParticipants[i].IdentityKey.KeyValue,
		) {
			return false
		}

		if !bytes.Equal(
			a.ActiveParticipants[i].SignedPreKey.KeyValue,
			b.ActiveParticipants[i].SignedPreKey.KeyValue,
		) {
			return false
		}
	}

	if len(a.NextRoundPreferredParticipants) !=
		len(b.NextRoundPreferredParticipants) {
		return false
	}

	for i := range a.NextRoundPreferredParticipants {
		if !bytes.Equal(
			a.NextRoundPreferredParticipants[i].KeyValue,
			b.NextRoundPreferredParticipants[i].KeyValue,
		) {
			return false
		}
	}

	if len(a.LatestSeenProverAttestations) !=
		len(b.LatestSeenProverAttestations) {
		return false
	}

	for i := range a.LatestSeenProverAttestations {
		if b.LatestSeenProverAttestations[i].ProverSignature == nil {
			return false
		}

		if b.LatestSeenProverAttestations[i].ProverSignature.PublicKey == nil {
			return false
		}

		if b.LatestSeenProverAttestations[i].SeenProverKey == nil {
			return false
		}

		if !bytes.Equal(
			a.LatestSeenProverAttestations[i].ProverSignature.Signature,
			b.LatestSeenProverAttestations[i].ProverSignature.Signature,
		) {
			return false
		}

		if !bytes.Equal(
			a.LatestSeenProverAttestations[i].ProverSignature.PublicKey.KeyValue,
			b.LatestSeenProverAttestations[i].ProverSignature.PublicKey.KeyValue,
		) {
			return false
		}

		if !bytes.Equal(
			a.LatestSeenProverAttestations[i].SeenProverKey.KeyValue,
			b.LatestSeenProverAttestations[i].SeenProverKey.KeyValue,
		) {
			return false
		}

		if a.LatestSeenProverAttestations[i].LastSeenFrame !=
			b.LatestSeenProverAttestations[i].LastSeenFrame {
			return false
		}
	}

	if len(a.DroppedParticipantAttestations) !=
		len(b.DroppedParticipantAttestations) {
		return false
	}

	for i := range a.DroppedParticipantAttestations {
		if b.DroppedParticipantAttestations[i].ProverSignature == nil {
			return false
		}

		if b.DroppedParticipantAttestations[i].ProverSignature.PublicKey == nil {
			return false
		}

		if b.DroppedParticipantAttestations[i].DroppedProverKey == nil {
			return false
		}

		if !bytes.Equal(
			a.DroppedParticipantAttestations[i].ProverSignature.Signature,
			b.DroppedParticipantAttestations[i].ProverSignature.Signature,
		) {
			return false
		}

		if !bytes.Equal(
			a.DroppedParticipantAttestations[i].ProverSignature.PublicKey.KeyValue,
			b.DroppedParticipantAttestations[i].ProverSignature.PublicKey.KeyValue,
		) {
			return false
		}

		if !bytes.Equal(
			a.DroppedParticipantAttestations[i].DroppedProverKey.KeyValue,
			b.DroppedParticipantAttestations[i].DroppedProverKey.KeyValue,
		) {
			return false
		}

		if a.DroppedParticipantAttestations[i].LastSeenFrame !=
			b.DroppedParticipantAttestations[i].LastSeenFrame {
			return false
		}
	}

	if len(a.LobbyJoins) != len(b.LobbyJoins) {
		return false
	}

	for i := range a.LobbyJoins {
		if b.LobbyJoins[i].IdentityKey == nil {
			return false
		}

		if b.LobbyJoins[i].SignedPreKey == nil {
			return false
		}

		if b.LobbyJoins[i].PublicKeySignatureEd448 == nil {
			return false
		}

		if !bytes.Equal(
			a.LobbyJoins[i].IdentityKey.KeyValue,
			b.LobbyJoins[i].IdentityKey.KeyValue,
		) {
			return false
		}

		if !bytes.Equal(
			a.LobbyJoins[i].SignedPreKey.KeyValue,
			b.LobbyJoins[i].SignedPreKey.KeyValue,
		) {
			return false
		}

		if !bytes.Equal(
			a.LobbyJoins[i].PublicKeySignatureEd448.Signature,
			b.LobbyJoins[i].PublicKeySignatureEd448.Signature,
		) {
			return false
		}

		if a.LobbyJoins[i].FrameNumber !=
			b.LobbyJoins[i].FrameNumber {
			return false
		}
	}

	if len(a.TranscriptRoundAdvanceCommits) !=
		len(b.TranscriptRoundAdvanceCommits) {
		return false
	}

	for i := range a.TranscriptRoundAdvanceCommits {
		if len(a.TranscriptRoundAdvanceCommits[i].Commits) !=
			len(b.TranscriptRoundAdvanceCommits[i].Commits) {
			return false
		}
		for j := range a.TranscriptRoundAdvanceCommits[i].Commits {
			ca := a.TranscriptRoundAdvanceCommits[i].Commits[j]
			cb := b.TranscriptRoundAdvanceCommits[i].Commits[j]

			if cb.ContributionSignature == nil {
				return false
			}

			if cb.ContributionSignature.PublicKey == nil {
				return false
			}

			if cb.ProverSignature == nil {
				return false
			}

			if cb.ProverSignature.PublicKey == nil {
				return false
			}

			if !bytes.Equal(
				ca.ContributionSignature.Signature,
				cb.ContributionSignature.Signature,
			) {
				return false
			}

			if !bytes.Equal(
				ca.ContributionSignature.PublicKey.KeyValue,
				cb.ContributionSignature.PublicKey.KeyValue,
			) {
				return false
			}

			if !bytes.Equal(
				ca.ProverSignature.Signature,
				cb.ProverSignature.Signature,
			) {
				return false
			}

			if !bytes.Equal(
				ca.ProverSignature.PublicKey.KeyValue,
				cb.ProverSignature.PublicKey.KeyValue,
			) {
				return false
			}
		}
	}

	if len(a.FinalCommits) != len(b.FinalCommits) {
		return false
	}

	for i := range a.FinalCommits {
		ca := a.FinalCommits[i]
		cb := b.FinalCommits[i]

		if cb.ContributionSignature == nil {
			return false
		}

		if cb.ContributionSignature.PublicKey == nil {
			return false
		}

		if cb.ProverSignature == nil {
			return false
		}

		if cb.ProverSignature.PublicKey == nil {
			return false
		}

		if !bytes.Equal(
			ca.ContributionSignature.Signature,
			cb.ContributionSignature.Signature,
		) {
			return false
		}

		if !bytes.Equal(
			ca.ContributionSignature.PublicKey.KeyValue,
			cb.ContributionSignature.PublicKey.KeyValue,
		) {
			return false
		}

		if !bytes.Equal(
			ca.ProverSignature.Signature,
			cb.ProverSignature.Signature,
		) {
			return false
		}

		if !bytes.Equal(
			ca.ProverSignature.PublicKey.KeyValue,
			cb.ProverSignature.PublicKey.KeyValue,
		) {
			return false
		}
	}

	if a.LatestTranscript == nil && b.LatestTranscript != nil ||
		a.LatestTranscript != nil && b.LatestTranscript == nil {
		return false
	}

	if a.LatestTranscript != nil {
		if len(a.LatestTranscript.G1Powers) !=
			len(b.LatestTranscript.G1Powers) {
			return false
		}

		if len(a.LatestTranscript.G2Powers) !=
			len(b.LatestTranscript.G2Powers) {
			return false
		}

		if len(a.LatestTranscript.RunningG1_256Witnesses) !=
			len(b.LatestTranscript.RunningG1_256Witnesses) {
			return false
		}

		if len(a.LatestTranscript.RunningG2_256Powers) !=
			len(b.LatestTranscript.RunningG2_256Powers) {
			return false
		}

		for i := range a.LatestTranscript.G1Powers {
			if !bytes.Equal(
				a.LatestTranscript.G1Powers[i].KeyValue,
				b.LatestTranscript.G1Powers[i].KeyValue,
			) {
				return false
			}
		}

		for i := range a.LatestTranscript.G2Powers {
			if !bytes.Equal(
				a.LatestTranscript.G2Powers[i].KeyValue,
				b.LatestTranscript.G2Powers[i].KeyValue,
			) {
				return false
			}
		}

		for i := range a.LatestTranscript.RunningG1_256Witnesses {
			if !bytes.Equal(
				a.LatestTranscript.RunningG1_256Witnesses[i].KeyValue,
				b.LatestTranscript.RunningG1_256Witnesses[i].KeyValue,
			) {
				return false
			}
		}

		for i := range a.LatestTranscript.RunningG2_256Powers {
			if !bytes.Equal(
				a.LatestTranscript.RunningG2_256Powers[i].KeyValue,
				b.LatestTranscript.RunningG2_256Powers[i].KeyValue,
			) {
				return false
			}
		}
	}

	ra, err := a.RewardTrie.Serialize()
	if err != nil {
		return false
	}

	rb, err := b.RewardTrie.Serialize()
	if err != nil {
		return false
	}

	if !bytes.Equal(ra, rb) {
		return false
	}

	if a.UpdatedTranscript == nil && b.UpdatedTranscript != nil ||
		a.UpdatedTranscript != nil && b.UpdatedTranscript == nil {
		return false
	}

	if a.UpdatedTranscript != nil {
		if len(a.UpdatedTranscript.G1Powers) !=
			len(b.UpdatedTranscript.G1Powers) {
			return false
		}

		if len(a.UpdatedTranscript.G2Powers) !=
			len(b.UpdatedTranscript.G2Powers) {
			return false
		}

		if len(a.UpdatedTranscript.RunningG1_256Witnesses) !=
			len(b.UpdatedTranscript.RunningG1_256Witnesses) {
			return false
		}

		if len(a.UpdatedTranscript.RunningG2_256Powers) !=
			len(b.UpdatedTranscript.RunningG2_256Powers) {
			return false
		}

		for i := range a.UpdatedTranscript.G1Powers {
			if !bytes.Equal(
				a.UpdatedTranscript.G1Powers[i].KeyValue,
				b.UpdatedTranscript.G1Powers[i].KeyValue,
			) {
				return false
			}
		}

		for i := range a.UpdatedTranscript.G2Powers {
			if !bytes.Equal(
				a.UpdatedTranscript.G2Powers[i].KeyValue,
				b.UpdatedTranscript.G2Powers[i].KeyValue,
			) {
				return false
			}
		}

		for i := range a.UpdatedTranscript.RunningG1_256Witnesses {
			if !bytes.Equal(
				a.UpdatedTranscript.RunningG1_256Witnesses[i].KeyValue,
				b.UpdatedTranscript.RunningG1_256Witnesses[i].KeyValue,
			) {
				return false
			}
		}

		for i := range a.UpdatedTranscript.RunningG2_256Powers {
			if !bytes.Equal(
				a.UpdatedTranscript.RunningG2_256Powers[i].KeyValue,
				b.UpdatedTranscript.RunningG2_256Powers[i].KeyValue,
			) {
				return false
			}
		}
	}

	if len(a.TranscriptShares) != len(b.TranscriptShares) {
		return false
	}

	for i := range a.TranscriptShares {
		if len(a.TranscriptShares[i].AdditiveG1Powers) !=
			len(b.TranscriptShares[i].AdditiveG1Powers) {
			return false
		}

		if len(a.TranscriptShares[i].AdditiveG2Powers) !=
			len(b.TranscriptShares[i].AdditiveG2Powers) {
			return false
		}

		for i := range a.TranscriptShares[i].AdditiveG1Powers {
			if !bytes.Equal(
				a.TranscriptShares[i].AdditiveG1Powers[i].KeyValue,
				b.TranscriptShares[i].AdditiveG1Powers[i].KeyValue,
			) {
				return false
			}
		}

		for i := range a.TranscriptShares[i].AdditiveG2Powers {
			if !bytes.Equal(
				a.TranscriptShares[i].AdditiveG2Powers[i].KeyValue,
				b.TranscriptShares[i].AdditiveG2Powers[i].KeyValue,
			) {
				return false
			}
		}

		if !bytes.Equal(
			a.TranscriptShares[i].AdditiveG1_256Witness.KeyValue,
			b.TranscriptShares[i].AdditiveG1_256Witness.KeyValue,
		) {
			return false
		}

		if !bytes.Equal(
			a.TranscriptShares[i].AdditiveG2_256Witness.KeyValue,
			b.TranscriptShares[i].AdditiveG2_256Witness.KeyValue,
		) {
			return false
		}
	}

	return true
}

func GetOutputsFromClockFrame(
	frame *protobufs.ClockFrame,
) (
	*protobufs.CeremonyLobbyStateTransition,
	*protobufs.CeremonyLobbyState,
	error,
) {
	var associatedProof []byte
	var lobbyState *protobufs.CeremonyLobbyState
	if len(frame.AggregateProofs) > 0 {
		for _, proofs := range frame.AggregateProofs {
			for _, inclusion := range proofs.InclusionCommitments {
				if inclusion.TypeUrl == protobufs.IntrinsicExecutionOutputType {
					output := protobufs.IntrinsicExecutionOutput{}
					if err := proto.Unmarshal(inclusion.Data, &output); err != nil {
						return nil, nil, errors.Wrap(err, "get outputs from clock frame")
					}

					// apply a small fixup based on a pre-dusk bug showing up with dusk
					// conventions
					if frame.FrameNumber == 0 && len(output.Address) == 32 {
						output.Address = append(output.Address, output.Output[:48]...)
						output.Output = output.Output[48:]
					}

					lobbyState = &protobufs.CeremonyLobbyState{}
					if err := proto.Unmarshal(output.Output, lobbyState); err != nil {
						return nil, nil, errors.Wrap(err, "get outputs from clock frame")
					}

					associatedProof = output.Proof
				}
			}
		}
	}

	transition := &protobufs.CeremonyLobbyStateTransition{}
	if err := proto.Unmarshal(associatedProof, transition); err != nil {
		return nil, nil, errors.Wrap(err, "get outputs from clock frame")
	}

	return transition, lobbyState, nil
}

func MaterializeApplicationFromFrame(
	frame *protobufs.ClockFrame,
) (*CeremonyApplication, error) {
	_, lobbyState, err := GetOutputsFromClockFrame(frame)
	if err != nil {
		return nil, errors.Wrap(err, "materialize application from frame")
	}

	rewardTrie := &tries.RewardCritbitTrie{}
	if err := rewardTrie.Deserialize(lobbyState.RewardTrie); err != nil {
		return nil, errors.Wrap(err, "materialize application from frame")
	}

	switch CeremonyApplicationState(lobbyState.LobbyState) {
	case CEREMONY_APPLICATION_STATE_OPEN:
		open := lobbyState.GetCeremonyOpenState()
		if open == nil {
			return nil, errors.Wrap(
				errors.New("missing open state"),
				"materialize application from frame",
			)
		}

		stateCount := uint64(0)

		if len(open.JoinedParticipants) > 0 {
			stateCount = frame.FrameNumber -
				open.JoinedParticipants[len(open.JoinedParticipants)-1].FrameNumber
		}

		return &CeremonyApplication{
			StateCount:                     stateCount,
			RoundCount:                     0,
			LobbyState:                     CEREMONY_APPLICATION_STATE_OPEN,
			LobbyJoins:                     open.JoinedParticipants,
			NextRoundPreferredParticipants: open.PreferredParticipants,
			LatestTranscript:               lobbyState.LatestTranscript,
			RewardTrie:                     rewardTrie,
		}, nil
	case CEREMONY_APPLICATION_STATE_IN_PROGRESS:
		inProgress := lobbyState.GetCeremonyInProgressState()
		if inProgress == nil {
			return nil, errors.Wrap(
				errors.New("missing in progress state"),
				"materialize application from frame",
			)
		}

		roundCount := len(inProgress.TranscriptRoundAdvanceCommits) + 1
		if roundCount > 1 &&
			len(inProgress.TranscriptRoundAdvanceCommits[roundCount-2].Commits) !=
				len(inProgress.ActiveParticipants) {
			roundCount--
		}

		stateCount := uint64(0)
		setCount := false

		if len(inProgress.DroppedParticipantAttestations) > 0 {
			stateCount = frame.FrameNumber -
				inProgress.DroppedParticipantAttestations[len(inProgress.DroppedParticipantAttestations)-1].LastSeenFrame
			setCount = true
		}

		if len(inProgress.LatestSeenProverAttestations) > 0 {
			seenCount := frame.FrameNumber -
				inProgress.LatestSeenProverAttestations[len(inProgress.LatestSeenProverAttestations)-1].LastSeenFrame
			if !setCount || seenCount < stateCount {
				stateCount = seenCount
			}
		}

		if len(inProgress.ActiveParticipants) > 0 {
			lastStateCount := frame.FrameNumber -
				inProgress.ActiveParticipants[len(inProgress.ActiveParticipants)-1].FrameNumber
			if !setCount || (lastStateCount < stateCount && lastStateCount > 20) {
				stateCount = lastStateCount
				if stateCount >= 10 {
					stateCount -= 10
				}
			}
		}

		return &CeremonyApplication{
			StateCount:                     stateCount,
			RoundCount:                     uint64(roundCount),
			LobbyState:                     CEREMONY_APPLICATION_STATE_IN_PROGRESS,
			NextRoundPreferredParticipants: inProgress.NextRoundParticipants,
			DroppedParticipantAttestations: inProgress.DroppedParticipantAttestations,
			LatestSeenProverAttestations:   inProgress.LatestSeenProverAttestations,
			ActiveParticipants:             inProgress.ActiveParticipants,
			LatestTranscript:               lobbyState.LatestTranscript,
			TranscriptRoundAdvanceCommits:  inProgress.TranscriptRoundAdvanceCommits,
			RewardTrie:                     rewardTrie,
		}, nil
	case CEREMONY_APPLICATION_STATE_FINALIZING:
		finalizing := lobbyState.GetCeremonyFinalizingState()
		if finalizing == nil {
			return nil, errors.Wrap(
				errors.New("missing finalizing state"),
				"materialize application from frame",
			)
		}

		stateCount := uint64(0)
		setCount := false

		if len(finalizing.DroppedParticipantAttestations) > 0 {
			stateCount = frame.FrameNumber -
				finalizing.DroppedParticipantAttestations[len(finalizing.DroppedParticipantAttestations)-1].LastSeenFrame
			setCount = true
		}

		if len(finalizing.LatestSeenProverAttestations) > 0 {
			seenCount := frame.FrameNumber -
				finalizing.LatestSeenProverAttestations[len(finalizing.LatestSeenProverAttestations)-1].LastSeenFrame
			if !setCount || seenCount < stateCount {
				stateCount = seenCount
			}
		}

		if len(finalizing.ActiveParticipants) > 0 {
			lastStateCount := frame.FrameNumber -
				finalizing.ActiveParticipants[len(finalizing.ActiveParticipants)-1].FrameNumber
			if !setCount || (lastStateCount < stateCount && lastStateCount > 200) {
				stateCount = lastStateCount - 200
			}
		}

		return &CeremonyApplication{
			StateCount:                     stateCount,
			RoundCount:                     0,
			LobbyState:                     CEREMONY_APPLICATION_STATE_FINALIZING,
			ActiveParticipants:             finalizing.ActiveParticipants,
			FinalCommits:                   finalizing.Commits,
			NextRoundPreferredParticipants: finalizing.NextRoundParticipants,
			DroppedParticipantAttestations: finalizing.DroppedParticipantAttestations,
			LatestSeenProverAttestations:   finalizing.LatestSeenProverAttestations,
			TranscriptShares:               finalizing.Shares,
			LatestTranscript:               lobbyState.LatestTranscript,
			RewardTrie:                     rewardTrie,
		}, nil
	case CEREMONY_APPLICATION_STATE_VALIDATING:
		validating := lobbyState.GetCeremonyValidatingState()
		if validating == nil {
			return nil, errors.Wrap(
				errors.New("missing validating state"),
				"materialize application from frame",
			)
		}

		return &CeremonyApplication{
			StateCount:                     0,
			RoundCount:                     0,
			LobbyState:                     CEREMONY_APPLICATION_STATE_VALIDATING,
			FinalCommits:                   validating.Commits,
			NextRoundPreferredParticipants: validating.NextRoundParticipants,
			LatestTranscript:               lobbyState.LatestTranscript,
			UpdatedTranscript:              validating.UpdatedTranscript,
			RewardTrie:                     rewardTrie,
		}, nil
	}

	return nil, errors.Wrap(
		errors.New("invalid state"),
		"materialize application from frame",
	)
}

func (a *CeremonyApplication) ApplyTransition(
	currentFrameNumber uint64,
	transition *protobufs.CeremonyLobbyStateTransition,
	skipFailures bool,
) (
	*CeremonyApplication,
	*protobufs.CeremonyLobbyStateTransition,
	*protobufs.CeremonyLobbyStateTransition,
	error,
) {
	finalizedTransition := &protobufs.CeremonyLobbyStateTransition{
		TypeUrls:         []string{},
		TransitionInputs: [][]byte{},
	}
	skippedTransition := &protobufs.CeremonyLobbyStateTransition{
		TypeUrls:         []string{},
		TransitionInputs: [][]byte{},
	}
	switch a.LobbyState {
	case CEREMONY_APPLICATION_STATE_OPEN:
		if a.StateCount > currentFrameNumber {
			a.StateCount = 0
		}
		a.StateCount++

		for i, url := range transition.TypeUrls {
			switch url {
			case protobufs.CeremonyLobbyJoinType:
				join := &protobufs.CeremonyLobbyJoin{}
				err := proto.Unmarshal(transition.TransitionInputs[i], join)
				if err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				if currentFrameNumber < join.FrameNumber {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("too recent join"), "apply transition",
						)
					}
					skippedTransition.TypeUrls = append(
						skippedTransition.TypeUrls,
						url,
					)
					skippedTransition.TransitionInputs = append(
						skippedTransition.TransitionInputs,
						transition.TransitionInputs[i],
					)
					continue
				}

				if currentFrameNumber-join.FrameNumber > 10 {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("outdated join"), "apply transition",
						)
					}
					continue
				}

				if err = a.applyLobbyJoin(join); err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				finalizedTransition.TypeUrls = append(
					finalizedTransition.TypeUrls,
					url,
				)
				finalizedTransition.TransitionInputs = append(
					finalizedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)

				a.StateCount = 0
			default:
				if !skipFailures {
					return a, nil, nil, nil
				}

				skippedTransition.TypeUrls = append(
					skippedTransition.TypeUrls,
					url,
				)
				skippedTransition.TransitionInputs = append(
					skippedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)
				continue
			}
		}

		if a.StateCount > 10 {
			if len(a.LobbyJoins) == 0 {
				return a, finalizedTransition, skippedTransition, nil
			}

			a.LobbyState = CEREMONY_APPLICATION_STATE_IN_PROGRESS
			a.StateCount = 0
			a.RoundCount = 1

			if err := a.finalizeParticipantSet(); err != nil {
				return nil, nil, nil, errors.Wrap(err, "apply transition")
			}

			a.LobbyJoins = []*protobufs.CeremonyLobbyJoin{}
		}

		return a, finalizedTransition, skippedTransition, nil
	case CEREMONY_APPLICATION_STATE_IN_PROGRESS:
		if a.StateCount > currentFrameNumber {
			a.StateCount = 0
		}
		a.StateCount++
		for i, url := range transition.TypeUrls {
			switch url {
			case protobufs.CeremonySeenProverAttestationType:
				seenProverAtt := &protobufs.CeremonySeenProverAttestation{}
				err := proto.Unmarshal(transition.TransitionInputs[i], seenProverAtt)
				if err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				if currentFrameNumber < seenProverAtt.LastSeenFrame {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("too recent attestation"), "apply transition",
						)
					}
					skippedTransition.TypeUrls = append(
						skippedTransition.TypeUrls,
						url,
					)
					skippedTransition.TransitionInputs = append(
						skippedTransition.TransitionInputs,
						transition.TransitionInputs[i],
					)
					continue
				}

				if currentFrameNumber-seenProverAtt.LastSeenFrame > 10 {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("outdated attestation"), "apply transition",
						)
					}
					continue
				}

				if err = a.applySeenProverAttestation(seenProverAtt); err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				finalizedTransition.TypeUrls = append(
					finalizedTransition.TypeUrls,
					url,
				)
				finalizedTransition.TransitionInputs = append(
					finalizedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)

				a.StateCount = 0
			case protobufs.CeremonyDroppedProverAttestationType:
				droppedProverAtt := &protobufs.CeremonyDroppedProverAttestation{}
				err := proto.Unmarshal(transition.TransitionInputs[i], droppedProverAtt)
				if err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				if currentFrameNumber < droppedProverAtt.LastSeenFrame {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("too recent attestation"), "apply transition",
						)
					}
					skippedTransition.TypeUrls = append(
						skippedTransition.TypeUrls,
						url,
					)
					skippedTransition.TransitionInputs = append(
						skippedTransition.TransitionInputs,
						transition.TransitionInputs[i],
					)
					continue
				}

				if currentFrameNumber-droppedProverAtt.LastSeenFrame > 10 {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("outdated attestation"), "apply transition",
						)
					}
					continue
				}

				if err = a.applyDroppedProverAttestation(droppedProverAtt); err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				finalizedTransition.TypeUrls = append(
					finalizedTransition.TypeUrls,
					url,
				)
				finalizedTransition.TransitionInputs = append(
					finalizedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)

				a.StateCount = 0
			case protobufs.CeremonyTranscriptCommitType:
				transcriptCommit := &protobufs.CeremonyTranscriptCommit{}
				err := proto.Unmarshal(transition.TransitionInputs[i], transcriptCommit)
				if err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				if err = a.applyTranscriptCommit(transcriptCommit); err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				finalizedTransition.TypeUrls = append(
					finalizedTransition.TypeUrls,
					url,
				)
				finalizedTransition.TransitionInputs = append(
					finalizedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)

				a.StateCount = 0
			default:
				if !skipFailures {
					return a, nil, nil, nil
				}

				skippedTransition.TypeUrls = append(
					skippedTransition.TypeUrls,
					url,
				)
				skippedTransition.TransitionInputs = append(
					skippedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)
				continue
			}
		}

		maxRounds := uint64(1)
		for i := 0; i < len(a.ActiveParticipants)-1; i++ {
			maxRounds = maxRounds << 1
		}

		if a.RoundCount >= maxRounds &&
			uint64(len(a.TranscriptRoundAdvanceCommits)) == a.RoundCount &&
			len(a.ActiveParticipants) ==
				len(a.TranscriptRoundAdvanceCommits[maxRounds-1].Commits) {
			a.LobbyState = CEREMONY_APPLICATION_STATE_FINALIZING
			a.FinalCommits = a.TranscriptRoundAdvanceCommits[a.RoundCount-1].Commits
			a.RoundCount = 0
			a.StateCount = 0
			a.DroppedParticipantAttestations =
				[]*protobufs.CeremonyDroppedProverAttestation{}
			a.LatestSeenProverAttestations =
				[]*protobufs.CeremonySeenProverAttestation{}
			a.TranscriptRoundAdvanceCommits =
				[]*protobufs.CeremonyAdvanceRound{}
			return a, finalizedTransition, skippedTransition, nil
		}

		attLimit := 1<<a.RoundCount - 1
		shouldReset := false
		droppedProversMap := map[string]int{}
		for _, att := range a.DroppedParticipantAttestations {
			if _, ok := droppedProversMap[string(
				att.DroppedProverKey.KeyValue,
			)]; !ok {
				droppedProversMap[string(att.DroppedProverKey.KeyValue)] = 0
			}

			droppedProversMap[string(att.DroppedProverKey.KeyValue)]++

			if droppedProversMap[string(att.DroppedProverKey.KeyValue)] >= attLimit {
				shouldReset = true
			}
		}

		if a.StateCount > 10 {
			shouldReset = true
		}

		if shouldReset {
			a.LobbyState = CEREMONY_APPLICATION_STATE_OPEN
			a.StateCount = 0
			a.RoundCount = 0
			for _, p := range a.ActiveParticipants {
				p := p
				if _, ok := droppedProversMap[string(
					p.PublicKeySignatureEd448.PublicKey.KeyValue,
				)]; !ok {
					a.NextRoundPreferredParticipants = append(
						append(
							[]*protobufs.Ed448PublicKey{},
							p.PublicKeySignatureEd448.PublicKey,
						),
						a.NextRoundPreferredParticipants...,
					)
				}
			}
			a.ActiveParticipants = []*protobufs.CeremonyLobbyJoin{}
			a.DroppedParticipantAttestations =
				[]*protobufs.CeremonyDroppedProverAttestation{}
			a.LatestSeenProverAttestations =
				[]*protobufs.CeremonySeenProverAttestation{}
			a.TranscriptRoundAdvanceCommits =
				[]*protobufs.CeremonyAdvanceRound{}
		}

		return a, finalizedTransition, skippedTransition, nil
	case CEREMONY_APPLICATION_STATE_FINALIZING:
		if a.StateCount > currentFrameNumber {
			a.StateCount = 0
		}
		a.StateCount++
		for i, url := range transition.TypeUrls {
			switch url {
			case protobufs.CeremonySeenProverAttestationType:
				seenProverAtt := &protobufs.CeremonySeenProverAttestation{}
				err := proto.Unmarshal(transition.TransitionInputs[i], seenProverAtt)
				if err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				if currentFrameNumber < seenProverAtt.LastSeenFrame {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("too recent attestation"), "apply transition",
						)
					}
					skippedTransition.TypeUrls = append(
						skippedTransition.TypeUrls,
						url,
					)
					skippedTransition.TransitionInputs = append(
						skippedTransition.TransitionInputs,
						transition.TransitionInputs[i],
					)
					continue
				}

				if currentFrameNumber-seenProverAtt.LastSeenFrame > 10 {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("outdated attestation"), "apply transition",
						)
					}
					continue
				}

				if err = a.applySeenProverAttestation(seenProverAtt); err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				finalizedTransition.TypeUrls = append(
					finalizedTransition.TypeUrls,
					url,
				)
				finalizedTransition.TransitionInputs = append(
					finalizedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)

				a.StateCount = 0
			case protobufs.CeremonyDroppedProverAttestationType:
				droppedProverAtt := &protobufs.CeremonyDroppedProverAttestation{}
				err := proto.Unmarshal(transition.TransitionInputs[i], droppedProverAtt)
				if err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				if currentFrameNumber < droppedProverAtt.LastSeenFrame {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("too recent attestation"), "apply transition",
						)
					}
					skippedTransition.TypeUrls = append(
						skippedTransition.TypeUrls,
						url,
					)
					skippedTransition.TransitionInputs = append(
						skippedTransition.TransitionInputs,
						transition.TransitionInputs[i],
					)
					continue
				}

				if currentFrameNumber-droppedProverAtt.LastSeenFrame > 10 {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("outdated attestation"), "apply transition",
						)
					}
					continue
				}

				if err = a.applyDroppedProverAttestation(droppedProverAtt); err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				finalizedTransition.TypeUrls = append(
					finalizedTransition.TypeUrls,
					url,
				)
				finalizedTransition.TransitionInputs = append(
					finalizedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)

				a.StateCount = 0
			case protobufs.CeremonyTranscriptShareType:
				transcriptShare := &protobufs.CeremonyTranscriptShare{}
				err := proto.Unmarshal(transition.TransitionInputs[i], transcriptShare)
				if err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				if err = a.applyTranscriptShare(transcriptShare); err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				finalizedTransition.TypeUrls = append(
					finalizedTransition.TypeUrls,
					url,
				)
				finalizedTransition.TransitionInputs = append(
					finalizedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)

				a.StateCount = 0
			default:
				if !skipFailures {
					return a, nil, nil, nil
				}

				skippedTransition.TypeUrls = append(
					skippedTransition.TypeUrls,
					url,
				)
				skippedTransition.TransitionInputs = append(
					skippedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)
				continue
			}
		}

		if len(a.TranscriptShares) == len(a.ActiveParticipants) {
			if err := a.finalizeTranscript(); err != nil {
				return nil, nil, nil, errors.Wrap(err, "apply transition")
			}

			a.LobbyState = CEREMONY_APPLICATION_STATE_VALIDATING
			a.ActiveParticipants = []*protobufs.CeremonyLobbyJoin{}
			a.DroppedParticipantAttestations =
				[]*protobufs.CeremonyDroppedProverAttestation{}
			a.LatestSeenProverAttestations =
				[]*protobufs.CeremonySeenProverAttestation{}
			return a, finalizedTransition, skippedTransition, nil
		}

		shouldReset := false
		droppedProversMap := map[string]int{}
		for _, att := range a.DroppedParticipantAttestations {
			if _, ok := droppedProversMap[string(
				att.DroppedProverKey.KeyValue,
			)]; !ok {
				droppedProversMap[string(att.DroppedProverKey.KeyValue)] = 0
			}

			droppedProversMap[string(att.DroppedProverKey.KeyValue)]++

			if droppedProversMap[string(att.DroppedProverKey.KeyValue)] >= len(
				a.ActiveParticipants,
			) {
				shouldReset = true
			}
		}

		if a.StateCount > 100 {
			shouldReset = true
		}

		if shouldReset {
			a.LobbyState = CEREMONY_APPLICATION_STATE_OPEN
			a.StateCount = 0
			a.RoundCount = 0
			for _, p := range a.ActiveParticipants {
				p := p
				if _, ok := droppedProversMap[string(
					p.PublicKeySignatureEd448.PublicKey.KeyValue,
				)]; !ok {
					a.NextRoundPreferredParticipants = append(
						append(
							[]*protobufs.Ed448PublicKey{},
							p.PublicKeySignatureEd448.PublicKey,
						),
						a.NextRoundPreferredParticipants...,
					)
				}
			}
			a.ActiveParticipants = []*protobufs.CeremonyLobbyJoin{}
			a.DroppedParticipantAttestations =
				[]*protobufs.CeremonyDroppedProverAttestation{}
			a.LatestSeenProverAttestations =
				[]*protobufs.CeremonySeenProverAttestation{}
			a.TranscriptRoundAdvanceCommits =
				[]*protobufs.CeremonyAdvanceRound{}
			a.TranscriptShares =
				[]*protobufs.CeremonyTranscriptShare{}
		}

		return a, finalizedTransition, skippedTransition, nil
	case CEREMONY_APPLICATION_STATE_VALIDATING:
		if a.StateCount > currentFrameNumber {
			a.StateCount = 0
		}
		a.StateCount++
		for i, url := range transition.TypeUrls {
			switch url {
			case protobufs.CeremonyTranscriptType:
				transcript := &protobufs.CeremonyTranscript{}
				err := proto.Unmarshal(transition.TransitionInputs[i], transcript)
				if err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				if err = a.applyTranscript(transcript); err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transition")
					}
					continue
				}

				finalizedTransition.TypeUrls = append(
					finalizedTransition.TypeUrls,
					url,
				)
				finalizedTransition.TransitionInputs = append(
					finalizedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)

				a.StateCount = 0
			default:
				if !skipFailures {
					return a, nil, nil, nil
				}
				skippedTransition.TypeUrls = append(
					skippedTransition.TypeUrls,
					url,
				)
				skippedTransition.TransitionInputs = append(
					skippedTransition.TransitionInputs,
					transition.TransitionInputs[i],
				)
				continue
			}
		}

		shouldReset := false
		if a.StateCount > 300 {
			shouldReset = true
		}

		if shouldReset {
			a.LobbyState = CEREMONY_APPLICATION_STATE_OPEN
			a.StateCount = 0
			a.RoundCount = 0
			a.ActiveParticipants = []*protobufs.CeremonyLobbyJoin{}
			a.DroppedParticipantAttestations =
				[]*protobufs.CeremonyDroppedProverAttestation{}
			a.LatestSeenProverAttestations =
				[]*protobufs.CeremonySeenProverAttestation{}
			a.TranscriptRoundAdvanceCommits =
				[]*protobufs.CeremonyAdvanceRound{}
			a.TranscriptShares =
				[]*protobufs.CeremonyTranscriptShare{}
		} else if a.UpdatedTranscript == nil {
			rewardMultiplier := uint64(1)
			for i := 0; i < len(a.FinalCommits)-1; i++ {
				rewardMultiplier = rewardMultiplier << 1
			}

			for _, c := range a.FinalCommits {
				h, err := poseidon.HashBytes(c.ProverSignature.PublicKey.KeyValue)
				if err != nil {
					panic(err)
				}

				addr := h.Bytes()
				addr = append(
					make([]byte, 32-len(addr)),
					addr...,
				)

				a.RewardTrie.Add(
					addr,
					currentFrameNumber,
					rewardMultiplier*161,
				)
			}

			a.LobbyState = CEREMONY_APPLICATION_STATE_OPEN
			a.StateCount = 0
			a.RoundCount = 0
			a.ActiveParticipants = []*protobufs.CeremonyLobbyJoin{}
			a.DroppedParticipantAttestations =
				[]*protobufs.CeremonyDroppedProverAttestation{}
			a.LatestSeenProverAttestations =
				[]*protobufs.CeremonySeenProverAttestation{}
			a.TranscriptRoundAdvanceCommits =
				[]*protobufs.CeremonyAdvanceRound{}
			a.TranscriptShares =
				[]*protobufs.CeremonyTranscriptShare{}
			a.FinalCommits = []*protobufs.CeremonyTranscriptCommit{}
		}

		return a, finalizedTransition, skippedTransition, nil
	default:
		return nil, nil, nil, errors.Wrap(ErrInvalidStateTransition, "apply transition")
	}
}

func (a *CeremonyApplication) MaterializeLobbyStateFromApplication() (
	*protobufs.CeremonyLobbyState,
	error,
) {
	var err error
	state := &protobufs.CeremonyLobbyState{}
	state.LobbyState = int32(a.LobbyState)
	state.LatestTranscript = a.LatestTranscript
	state.RewardTrie, err = a.RewardTrie.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "materialize lobby state from application")
	}

	switch a.LobbyState {
	case CEREMONY_APPLICATION_STATE_OPEN:
		state.CeremonyState = &protobufs.CeremonyLobbyState_CeremonyOpenState{
			CeremonyOpenState: &protobufs.CeremonyOpenState{
				JoinedParticipants:    a.LobbyJoins,
				PreferredParticipants: a.NextRoundPreferredParticipants,
			},
		}
	case CEREMONY_APPLICATION_STATE_IN_PROGRESS:
		state.CeremonyState = &protobufs.CeremonyLobbyState_CeremonyInProgressState{
			CeremonyInProgressState: &protobufs.CeremonyInProgressState{
				ActiveParticipants:             a.ActiveParticipants,
				LatestSeenProverAttestations:   a.LatestSeenProverAttestations,
				DroppedParticipantAttestations: a.DroppedParticipantAttestations,
				TranscriptRoundAdvanceCommits:  a.TranscriptRoundAdvanceCommits,
				NextRoundParticipants:          a.NextRoundPreferredParticipants,
			},
		}
	case CEREMONY_APPLICATION_STATE_FINALIZING:
		state.CeremonyState = &protobufs.CeremonyLobbyState_CeremonyFinalizingState{
			CeremonyFinalizingState: &protobufs.CeremonyFinalizingState{
				ActiveParticipants:             a.ActiveParticipants,
				LatestSeenProverAttestations:   a.LatestSeenProverAttestations,
				DroppedParticipantAttestations: a.DroppedParticipantAttestations,
				Commits:                        a.FinalCommits,
				Shares:                         a.TranscriptShares,
				NextRoundParticipants:          a.NextRoundPreferredParticipants,
			},
		}
	case CEREMONY_APPLICATION_STATE_VALIDATING:
		state.CeremonyState = &protobufs.CeremonyLobbyState_CeremonyValidatingState{
			CeremonyValidatingState: &protobufs.CeremonyValidatingState{
				Commits:               a.FinalCommits,
				UpdatedTranscript:     a.UpdatedTranscript,
				NextRoundParticipants: a.NextRoundPreferredParticipants,
			},
		}
	}

	return state, nil
}
