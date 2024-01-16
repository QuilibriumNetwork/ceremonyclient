package application

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *CeremonyApplication) applySeenProverAttestation(
	seenProverAttestation *protobufs.CeremonySeenProverAttestation,
) error {
	if seenProverAttestation.SeenProverKey == nil ||
		seenProverAttestation.SeenProverKey.KeyValue == nil {
		return errors.Wrap(
			errors.New("signature is nil"),
			"apply seen prover attestation",
		)
	}

	inParticipantList := false
	for _, p := range a.ActiveParticipants {
		if bytes.Equal(
			p.PublicKeySignatureEd448.PublicKey.KeyValue,
			seenProverAttestation.SeenProverKey.KeyValue,
		) {
			inParticipantList = true
			break
		}
	}

	if !inParticipantList {
		return errors.Wrap(
			errors.New("prover not in active participant list"),
			"apply seen prover attestation",
		)
	}

	b := binary.BigEndian.AppendUint64(
		[]byte("lastseen"),
		seenProverAttestation.LastSeenFrame,
	)
	b = append(b, seenProverAttestation.SeenProverKey.KeyValue...)
	signature := seenProverAttestation.GetProverSignature()
	if signature == nil {
		return errors.Wrap(
			errors.New("signature is nil"),
			"apply seen prover attestation",
		)
	}

	if err := signature.Verify(b); err != nil {
		return errors.Wrap(err, "apply seen prover attestation")
	}

	replaced := false
	for i, att := range a.LatestSeenProverAttestations {
		att := att
		if bytes.Equal(
			att.SeenProverKey.KeyValue,
			seenProverAttestation.SeenProverKey.KeyValue,
		) &&
			bytes.Equal(
				att.ProverSignature.PublicKey.KeyValue,
				seenProverAttestation.ProverSignature.PublicKey.KeyValue,
			) && att.LastSeenFrame < seenProverAttestation.LastSeenFrame {
			a.LatestSeenProverAttestations[i] = att
			replaced = true
			break
		}
	}

	if !replaced {
		a.LatestSeenProverAttestations = append(
			a.LatestSeenProverAttestations,
			seenProverAttestation,
		)
	}

	return nil
}

func (a *CeremonyApplication) applyDroppedProverAttestation(
	droppedProverAttestation *protobufs.CeremonyDroppedProverAttestation,
) error {
	if droppedProverAttestation.DroppedProverKey == nil ||
		droppedProverAttestation.DroppedProverKey.KeyValue == nil {
		return errors.Wrap(
			errors.New("signature is nil"),
			"apply dropped prover attestation",
		)
	}

	inParticipantList := false
	for _, p := range a.ActiveParticipants {
		if bytes.Equal(
			p.PublicKeySignatureEd448.PublicKey.KeyValue,
			droppedProverAttestation.DroppedProverKey.KeyValue,
		) {
			inParticipantList = true
			break
		}
	}

	if !inParticipantList {
		return errors.Wrap(
			errors.New("prover not in active participant list"),
			"apply dropped prover attestation",
		)
	}

	b := binary.BigEndian.AppendUint64(
		[]byte("dropped"),
		droppedProverAttestation.LastSeenFrame,
	)
	b = append(b, droppedProverAttestation.DroppedProverKey.KeyValue...)
	signature := droppedProverAttestation.GetProverSignature()
	if signature == nil {
		return errors.Wrap(
			errors.New("signature is nil"),
			"apply dropped prover attestation",
		)
	}

	if err := signature.Verify(b); err != nil {
		return errors.Wrap(err, "apply dropped prover attestation")
	}

	replaced := false
	for i, att := range a.DroppedParticipantAttestations {
		att := att
		if bytes.Equal(
			att.DroppedProverKey.KeyValue,
			droppedProverAttestation.DroppedProverKey.KeyValue,
		) &&
			bytes.Equal(
				att.ProverSignature.PublicKey.KeyValue,
				droppedProverAttestation.ProverSignature.PublicKey.KeyValue,
			) && att.LastSeenFrame < droppedProverAttestation.LastSeenFrame {
			a.DroppedParticipantAttestations[i] = att
			replaced = true
			break
		}
	}

	if !replaced {
		a.DroppedParticipantAttestations = append(
			a.DroppedParticipantAttestations,
			droppedProverAttestation,
		)
	}

	return nil
}

func (a *CeremonyApplication) applyTranscriptCommit(
	transcriptCommit *protobufs.CeremonyTranscriptCommit,
) error {
	if transcriptCommit.ContributionSignature == nil ||
		transcriptCommit.ProverSignature == nil ||
		transcriptCommit.ContributionSignature.PublicKey == nil ||
		transcriptCommit.ProverSignature.PublicKey == nil {
		return errors.Wrap(
			errors.New("signature is nil"),
			"apply transcript commit",
		)
	}

	point, err := curves.BLS48581G2().Point.FromAffineCompressed(
		transcriptCommit.ContributionSignature.PublicKey.KeyValue,
	)
	if err != nil {
		return errors.Wrap(err, "apply transcript commit")
	}

	if err := VerifySignatureOfProverKey(
		transcriptCommit.ProverSignature.PublicKey.KeyValue,
		transcriptCommit.ContributionSignature.Signature,
		point,
	); err != nil {
		return errors.Wrap(err, "apply transcript commit")
	}

	if err := transcriptCommit.ProverSignature.Verify(
		transcriptCommit.ContributionSignature.PublicKey.KeyValue,
	); err != nil {
		return errors.Wrap(err, "apply transcript commit")
	}

	inParticipantList := false
	for _, p := range a.ActiveParticipants {
		if bytes.Equal(
			p.PublicKeySignatureEd448.PublicKey.KeyValue,
			transcriptCommit.ProverSignature.PublicKey.KeyValue,
		) {
			inParticipantList = true
			break
		}
	}

	if !inParticipantList {
		return errors.Wrap(
			errors.New("prover not in active participant list"),
			"apply transcript commit",
		)
	}

	maxRounds := uint64(1)
	for i := 0; i < len(a.ActiveParticipants)-1; i++ {
		maxRounds = maxRounds << 1
	}

	if len(a.TranscriptRoundAdvanceCommits) == 0 {
		a.TranscriptRoundAdvanceCommits = []*protobufs.CeremonyAdvanceRound{
			{
				Commits: []*protobufs.CeremonyTranscriptCommit{},
			},
		}
	}

	if maxRounds < a.RoundCount-1 {
		return errors.Wrap(
			errors.New("round limit exceeded"),
			"apply transcript commit",
		)
	}

	if len(a.TranscriptRoundAdvanceCommits[a.RoundCount-1].Commits) ==
		len(a.ActiveParticipants) {
		a.TranscriptRoundAdvanceCommits = append(
			a.TranscriptRoundAdvanceCommits,
			&protobufs.CeremonyAdvanceRound{
				Commits: []*protobufs.CeremonyTranscriptCommit{
					transcriptCommit,
				},
			},
		)
		a.RoundCount++
	} else {
		for _, c := range a.TranscriptRoundAdvanceCommits[a.RoundCount-1].Commits {
			if bytes.Equal(
				c.ProverSignature.PublicKey.KeyValue,
				transcriptCommit.ProverSignature.PublicKey.KeyValue,
			) {
				return nil
			}
		}
		a.TranscriptRoundAdvanceCommits[a.RoundCount-1].Commits = append(
			a.TranscriptRoundAdvanceCommits[a.RoundCount-1].Commits,
			transcriptCommit,
		)
	}

	return nil
}
